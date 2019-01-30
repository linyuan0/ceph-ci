// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2016 John Spray <john.spray@redhat.com>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 */

#include "DaemonServer.h"
#include "mgr/Mgr.h"

#include "include/stringify.h"
#include "include/str_list.h"
#include "auth/RotatingKeyRing.h"
#include "json_spirit/json_spirit_writer.h"

#include "mgr/mgr_commands.h"
#include "mgr/OSDHealthMetricCollector.h"
#include "mon/MonCommand.h"

#include "messages/MMgrOpen.h"
#include "messages/MMgrConfigure.h"
#include "messages/MMonMgrReport.h"
#include "messages/MCommand.h"
#include "messages/MCommandReply.h"
#include "messages/MPGStats.h"
#include "messages/MOSDScrub.h"
#include "messages/MOSDForceRecovery.h"
#include "messages/MOSDResetRecoveryLimits.h"
#include "common/errno.h"

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_mgr
#undef dout_prefix
#define dout_prefix *_dout << "mgr.server " << __func__ << " "



DaemonServer::DaemonServer(MonClient *monc_,
                           Finisher &finisher_,
			   DaemonStateIndex &daemon_state_,
			   ClusterState &cluster_state_,
			   PyModuleRegistry &py_modules_,
			   LogChannelRef clog_,
			   LogChannelRef audit_clog_)
    : Dispatcher(g_ceph_context),
      client_byte_throttler(new Throttle(g_ceph_context, "mgr_client_bytes",
					 g_conf->get_val<uint64_t>("mgr_client_bytes"))),
      client_msg_throttler(new Throttle(g_ceph_context, "mgr_client_messages",
					g_conf->get_val<uint64_t>("mgr_client_messages"))),
      osd_byte_throttler(new Throttle(g_ceph_context, "mgr_osd_bytes",
				      g_conf->get_val<uint64_t>("mgr_osd_bytes"))),
      osd_msg_throttler(new Throttle(g_ceph_context, "mgr_osd_messsages",
				     g_conf->get_val<uint64_t>("mgr_osd_messages"))),
      mds_byte_throttler(new Throttle(g_ceph_context, "mgr_mds_bytes",
				      g_conf->get_val<uint64_t>("mgr_mds_bytes"))),
      mds_msg_throttler(new Throttle(g_ceph_context, "mgr_mds_messsages",
				     g_conf->get_val<uint64_t>("mgr_mds_messages"))),
      mon_byte_throttler(new Throttle(g_ceph_context, "mgr_mon_bytes",
				      g_conf->get_val<uint64_t>("mgr_mon_bytes"))),
      mon_msg_throttler(new Throttle(g_ceph_context, "mgr_mon_messsages",
				     g_conf->get_val<uint64_t>("mgr_mon_messages"))),
      msgr(nullptr),
      monc(monc_),
      finisher(finisher_),
      daemon_state(daemon_state_),
      cluster_state(cluster_state_),
      py_modules(py_modules_),
      clog(clog_),
      audit_clog(audit_clog_),
      auth_cluster_registry(g_ceph_context,
                    g_conf->auth_supported.empty() ?
                      g_conf->auth_cluster_required :
                      g_conf->auth_supported),
      auth_service_registry(g_ceph_context,
                   g_conf->auth_supported.empty() ?
                      g_conf->auth_service_required :
                      g_conf->auth_supported),
      lock("DaemonServer"),
      timer(g_ceph_context, lock),
      pgmap_ready(false)
{
  g_conf->add_observer(this);
}

DaemonServer::~DaemonServer() {
  delete msgr;
  g_conf->remove_observer(this);
}

int DaemonServer::init(uint64_t gid, entity_addr_t client_addr)
{
  // Initialize Messenger
  std::string public_msgr_type = g_conf->ms_public_type.empty() ?
    g_conf->get_val<std::string>("ms_type") : g_conf->ms_public_type;
  msgr = Messenger::create(g_ceph_context, public_msgr_type,
			   entity_name_t::MGR(gid),
			   "mgr",
			   getpid(), 0);
  msgr->set_default_policy(Messenger::Policy::stateless_server(0));

  // throttle clients
  msgr->set_policy_throttlers(entity_name_t::TYPE_CLIENT,
			      client_byte_throttler.get(),
			      client_msg_throttler.get());

  // servers
  msgr->set_policy_throttlers(entity_name_t::TYPE_OSD,
			      osd_byte_throttler.get(),
			      osd_msg_throttler.get());
  msgr->set_policy_throttlers(entity_name_t::TYPE_MDS,
			      mds_byte_throttler.get(),
			      mds_msg_throttler.get());
  msgr->set_policy_throttlers(entity_name_t::TYPE_MON,
			      mon_byte_throttler.get(),
			      mon_msg_throttler.get());

  int r = msgr->bind(g_conf->public_addr);
  if (r < 0) {
    derr << "unable to bind mgr to " << g_conf->public_addr << dendl;
    return r;
  }

  msgr->set_myname(entity_name_t::MGR(gid));
  msgr->set_addr_unknowns(client_addr);

  msgr->start();
  msgr->add_dispatcher_tail(this);

  last_adjust = started_at = ceph_clock_now();
  timer.init();
  perf_stat_start();

  m_daemon_hook = new MgrDaemonHook(this);
  AdminSocket* admin_socket = cct->get_admin_socket();
  int ret = admin_socket->register_command("dump_image_perf",
                                           "dump_image_perf",
                                           m_daemon_hook,
                                           "show opened rbd images performance");
  if (ret < 0 && ret != -EEXIST) {
    derr << "error registering admin socket command dump_image_perf: "
         << cpp_strerror(ret) << dendl;
  }

  ret = admin_socket->register_command("dump_cluster_state",
                                       "dump_cluster_state",
                                       m_daemon_hook,
                                       "show cluster state of mgr daemon");
  if (ret < 0 && ret != -EEXIST) {
    derr << "error registering admin socket command dump_cluster_state: "
         << cpp_strerror(ret) << dendl;
  }

  return 0;
}

entity_addr_t DaemonServer::get_myaddr() const
{
  return msgr->get_myaddr();
}


bool DaemonServer::ms_verify_authorizer(
  Connection *con,
  int peer_type,
  int protocol,
  ceph::bufferlist& authorizer_data,
  ceph::bufferlist& authorizer_reply,
  bool& is_valid,
  CryptoKey& session_key,
  std::unique_ptr<AuthAuthorizerChallenge> *challenge)
{
  AuthAuthorizeHandler *handler = nullptr;
  if (peer_type == CEPH_ENTITY_TYPE_OSD ||
      peer_type == CEPH_ENTITY_TYPE_MON ||
      peer_type == CEPH_ENTITY_TYPE_MDS ||
      peer_type == CEPH_ENTITY_TYPE_MGR) {
    handler = auth_cluster_registry.get_handler(protocol);
  } else {
    handler = auth_service_registry.get_handler(protocol);
  }
  if (!handler) {
    dout(0) << "No AuthAuthorizeHandler found for protocol " << protocol << dendl;
    is_valid = false;
    return true;
  }

  MgrSessionRef s(new MgrSession(cct));
  s->inst.addr = con->get_peer_addr();
  AuthCapsInfo caps_info;

  RotatingKeyRing *keys = monc->rotating_secrets.get();
  if (keys) {
    is_valid = handler->verify_authorizer(
      cct, keys,
      authorizer_data,
      authorizer_reply, s->entity_name,
      s->global_id, caps_info,
      session_key,
      nullptr,
      challenge);
  } else {
    dout(10) << __func__ << " no rotating_keys (yet), denied" << dendl;
    is_valid = false;
  }

  if (is_valid) {
    if (caps_info.allow_all) {
      dout(10) << " session " << s << " " << s->entity_name
	       << " allow_all" << dendl;
      s->caps.set_allow_all();
    }
    if (caps_info.caps.length() > 0) {
      bufferlist::iterator p = caps_info.caps.begin();
      string str;
      try {
	::decode(str, p);
      }
      catch (buffer::error& e) {
      }
      bool success = s->caps.parse(str);
      if (success) {
	dout(10) << " session " << s << " " << s->entity_name
		 << " has caps " << s->caps << " '" << str << "'" << dendl;
      } else {
	dout(10) << " session " << s << " " << s->entity_name
		 << " failed to parse caps '" << str << "'" << dendl;
	is_valid = false;
      }
    }
    con->set_priv(s->get());

    if (peer_type == CEPH_ENTITY_TYPE_OSD) {
      Mutex::Locker l(lock);
      s->osd_id = atoi(s->entity_name.get_id().c_str());
      dout(10) << "registering osd." << s->osd_id << " session "
	       << s << " con " << con << dendl;
      osd_cons[s->osd_id].insert(con);
    }
  }

  return true;
}


bool DaemonServer::ms_get_authorizer(int dest_type,
    AuthAuthorizer **authorizer, bool force_new)
{
  dout(10) << "type=" << ceph_entity_type_name(dest_type) << dendl;

  if (dest_type == CEPH_ENTITY_TYPE_MON) {
    return true;
  }

  if (force_new) {
    if (monc->wait_auth_rotating(10) < 0)
      return false;
  }

  *authorizer = monc->build_authorizer(dest_type);
  dout(20) << "got authorizer " << *authorizer << dendl;
  return *authorizer != NULL;
}

bool DaemonServer::ms_handle_reset(Connection *con)
{
  if (con->get_peer_type() == CEPH_ENTITY_TYPE_OSD) {
    auto priv = con->get_priv();
    auto session = static_cast<MgrSession*>(priv.get());
    if (!session) {
      return false;
    }
    Mutex::Locker l(lock);
    dout(10) << "unregistering osd." << session->osd_id
	     << "  session " << session << " con " << con << dendl;
    osd_cons[session->osd_id].erase(con);

    auto iter = daemon_connections.find(con);
    if (iter != daemon_connections.end()) {
      daemon_connections.erase(iter);
    }
  }
  return false;
}

bool DaemonServer::ms_handle_refused(Connection *con)
{
  // do nothing for now
  return false;
}

bool DaemonServer::ms_dispatch(Message *m)
{
  // Note that we do *not* take ::lock here, in order to avoid
  // serializing all message handling.  It's up to each handler
  // to take whatever locks it needs.
  switch (m->get_type()) {
    case MSG_PGSTATS:
      cluster_state.ingest_pgstats(static_cast<MPGStats*>(m));
      maybe_ready(m->get_source().num());
      m->put();
      return true;
    case MSG_MGR_REPORT:
      return handle_report(static_cast<MMgrReport*>(m));
    case MSG_MGR_OPEN:
      return handle_open(static_cast<MMgrOpen*>(m));
    case MSG_COMMAND:
      return handle_command(static_cast<MCommand*>(m));
    default:
      dout(1) << "Unhandled message type " << m->get_type() << dendl;
      return false;
  };
}

void DaemonServer::maybe_ready(int32_t osd_id)
{
  if (pgmap_ready.load()) {
    // Fast path: we don't need to take lock because pgmap_ready
    // is already set
  } else {
    Mutex::Locker l(lock);

    if (reported_osds.find(osd_id) == reported_osds.end()) {
      dout(4) << "initial report from osd " << osd_id << dendl;
      reported_osds.insert(osd_id);
      std::set<int32_t> up_osds;

      cluster_state.with_osdmap([&](const OSDMap& osdmap) {
          osdmap.get_up_osds(up_osds);
      });

      std::set<int32_t> unreported_osds;
      std::set_difference(up_osds.begin(), up_osds.end(),
                          reported_osds.begin(), reported_osds.end(),
                          std::inserter(unreported_osds, unreported_osds.begin()));

      if (unreported_osds.size() == 0) {
        dout(4) << "all osds have reported, sending PG state to mon" << dendl;
        pgmap_ready = true;
        reported_osds.clear();
        // Avoid waiting for next tick
        send_report();
      } else {
        dout(4) << "still waiting for " << unreported_osds.size() << " osds"
                   " to report in before PGMap is ready" << dendl;
      }
    }
  }
}

void DaemonServer::shutdown()
{
  dout(10) << "begin" << dendl;
  msgr->shutdown();
  msgr->wait();
  cluster_state.shutdown();
  {
    Mutex::Locker l(lock);
    timer.shutdown();
  }
  if (m_daemon_hook) {
    AdminSocket* admin_socket = cct->get_admin_socket();
    admin_socket->unregister_command("dump_image_perf");
    admin_socket->unregister_command("dump_cluster_state");
    delete m_daemon_hook;
    m_daemon_hook = nullptr;
  }
  dout(10) << "done" << dendl;
}



bool DaemonServer::handle_open(MMgrOpen *m)
{
  Mutex::Locker l(lock);

  DaemonKey key;
  if (!m->service_name.empty()) {
    key.first = m->service_name;
  } else {
    key.first = ceph_entity_type_name(m->get_connection()->get_peer_type());
  }
  key.second = m->daemon_name;

  dout(4) << "from " << m->get_connection() << "  " << key << dendl;

  _send_configure(m->get_connection());

  DaemonStatePtr daemon;
  if (daemon_state.exists(key)) {
    daemon = daemon_state.get(key);
  }
  if (daemon) {
    dout(20) << "updating existing DaemonState for " << m->daemon_name << dendl;
    Mutex::Locker l(daemon->lock);
    daemon->perf_counters.clear();
  }

  if (m->service_daemon) {
    if (!daemon) {
      dout(4) << "constructing new DaemonState for " << key << dendl;
      daemon = std::make_shared<DaemonState>(daemon_state.types);
      daemon->key = key;
      if (m->daemon_metadata.count("hostname")) {
        daemon->hostname = m->daemon_metadata["hostname"];
      }
      daemon_state.insert(daemon);
    }
    Mutex::Locker l(daemon->lock);
    daemon->service_daemon = true;
    daemon->metadata = m->daemon_metadata;
    daemon->service_status = m->daemon_status;

    utime_t now = ceph_clock_now();
    auto d = pending_service_map.get_daemon(m->service_name,
					    m->daemon_name);
    if (d->gid != (uint64_t)m->get_source().num()) {
      dout(10) << "registering " << key << " in pending_service_map" << dendl;
      d->gid = m->get_source().num();
      d->addr = m->get_source_addr();
      d->start_epoch = pending_service_map.epoch;
      d->start_stamp = now;
      d->metadata = m->daemon_metadata;
      pending_service_map_dirty = pending_service_map.epoch;
    }
  }

  if (m->get_connection()->get_peer_type() != entity_name_t::TYPE_CLIENT &&
      m->service_name.empty())
  {
    // Store in set of the daemon/service connections, i.e. those
    // connections that require an update in the event of stats
    // configuration changes.
    daemon_connections.insert(m->get_connection());
  }

  m->put();
  return true;
}

bool DaemonServer::handle_report(MMgrReport *m)
{
  DaemonKey key;
  if (!m->service_name.empty()) {
    key.first = m->service_name;
  } else {
    key.first = ceph_entity_type_name(m->get_connection()->get_peer_type());
  }
  key.second = m->daemon_name;

  dout(4) << "from " << m->get_connection() << " " << key << dendl;

  if (m->get_connection()->get_peer_type() == entity_name_t::TYPE_CLIENT &&
      m->service_name.empty()) {
    // Clients should not be sending us stats unless they are declaring
    // themselves to be a daemon for some service.
    dout(4) << "rejecting report from non-daemon client " << m->daemon_name
	    << dendl;
    m->get_connection()->mark_down();
    m->put();
    return true;
  }

  // Look up the DaemonState
  DaemonStatePtr daemon;
  if (daemon_state.exists(key)) {
    dout(20) << "updating existing DaemonState for " << key << dendl;
    daemon = daemon_state.get(key);
  } else {
    // we don't know the hostname at this stage, reject MMgrReport here.
    dout(5) << "rejecting report from " << key << ", since we do not have its metadata now."
	    << dendl;

    // issue metadata request in background
    if (!daemon_state.is_updating(key) && 
	(key.first == "osd" || key.first == "mds")) {

      std::ostringstream oss;
      auto c = new MetadataUpdate(daemon_state, key);
      if (key.first == "osd") {
        oss << "{\"prefix\": \"osd metadata\", \"id\": "
            << key.second<< "}";

      } else if (key.first == "mds") {
        c->set_default("addr", stringify(m->get_source_addr()));
        oss << "{\"prefix\": \"mds metadata\", \"who\": \""
            << key.second << "\"}";
 
      } else {
	ceph_abort();
      }

      monc->start_mon_command({oss.str()}, {}, &c->outbl, &c->outs, c);
    }
    
    {
      Mutex::Locker l(lock);
      // kill session
      auto priv = m->get_connection()->get_priv();
      auto session = static_cast<MgrSession*>(priv.get());
      if (!session) {
	return false;
      }
      m->get_connection()->mark_down();

      dout(10) << "unregistering osd." << session->osd_id
	       << "  session " << session << " con " << m->get_connection() << dendl;
      
      if (osd_cons.find(session->osd_id) != osd_cons.end()) {
	   osd_cons[session->osd_id].erase(m->get_connection());
      } 

      auto iter = daemon_connections.find(m->get_connection());
      if (iter != daemon_connections.end()) {
	daemon_connections.erase(iter);
      }
    }

    return false;
  }

  // Update the DaemonState
  assert(daemon != nullptr);
  {
    Mutex::Locker l(daemon->lock);
    auto &daemon_counters = daemon->perf_counters;
    daemon_counters.update(m);

    if (daemon->service_daemon) {
      utime_t now = ceph_clock_now();
      if (m->daemon_status) {
        daemon->service_status = *m->daemon_status;
        daemon->service_status_stamp = now;
      }
      daemon->last_service_beacon = now;
    } else if (m->daemon_status) {
      derr << "got status from non-daemon " << key << dendl;
    }
    if (m->get_connection()->peer_is_osd()) {
      // only OSD sends health_checks to me now
      daemon->osd_health_metrics = std::move(m->osd_health_metrics);
    }
  }

  // if there are any schema updates, notify the python modules
  if (!m->declare_types.empty() || !m->undeclare_types.empty()) {
    ostringstream oss;
    oss << key.first << '.' << key.second;
    py_modules.notify_all("perf_schema_update", oss.str());
  }

  m->put();
  return true;
}


void DaemonServer::_generate_command_map(
  map<string,cmd_vartype>& cmdmap,
  map<string,string> &param_str_map)
{
  for (map<string,cmd_vartype>::const_iterator p = cmdmap.begin();
       p != cmdmap.end(); ++p) {
    if (p->first == "prefix")
      continue;
    if (p->first == "caps") {
      vector<string> cv;
      if (cmd_getval(g_ceph_context, cmdmap, "caps", cv) &&
	  cv.size() % 2 == 0) {
	for (unsigned i = 0; i < cv.size(); i += 2) {
	  string k = string("caps_") + cv[i];
	  param_str_map[k] = cv[i + 1];
	}
	continue;
      }
    }
    param_str_map[p->first] = cmd_vartype_stringify(p->second);
  }
}

const MonCommand *DaemonServer::_get_mgrcommand(
  const string &cmd_prefix,
  const std::vector<MonCommand> &cmds)
{
  const MonCommand *this_cmd = nullptr;
  for (const auto &cmd : cmds) {
    if (cmd.cmdstring.compare(0, cmd_prefix.size(), cmd_prefix) == 0) {
      this_cmd = &cmd;
      break;
    }
  }
  return this_cmd;
}

bool DaemonServer::_allowed_command(
  MgrSession *s,
  const string &module,
  const string &prefix,
  const map<string,cmd_vartype>& cmdmap,
  const map<string,string>& param_str_map,
  const MonCommand *this_cmd) {

  if (s->entity_name.is_mon()) {
    // mon is all-powerful.  even when it is forwarding commands on behalf of
    // old clients; we expect the mon is validating commands before proxying!
    return true;
  }

  bool cmd_r = this_cmd->requires_perm('r');
  bool cmd_w = this_cmd->requires_perm('w');
  bool cmd_x = this_cmd->requires_perm('x');

  bool capable = s->caps.is_capable(
    g_ceph_context,
    CEPH_ENTITY_TYPE_MGR,
    s->entity_name,
    module, prefix, param_str_map,
    cmd_r, cmd_w, cmd_x);

  dout(10) << " " << s->entity_name << " "
	   << (capable ? "" : "not ") << "capable" << dendl;
  return capable;
}

bool DaemonServer::handle_command(MCommand *m)
{
  Mutex::Locker l(lock);
  int r = 0;
  std::stringstream ss;
  std::string prefix;

  assert(lock.is_locked_by_me());

  /**
   * The working data for processing an MCommand.  This lives in
   * a class to enable passing it into other threads for processing
   * outside of the thread/locks that called handle_command.
   */
  class CommandContext
  {
    public:
    MCommand *m;
    bufferlist odata;
    cmdmap_t cmdmap;

    CommandContext(MCommand *m_)
      : m(m_)
    {
    }

    ~CommandContext()
    {
      m->put();
    }

    void reply(int r, const std::stringstream &ss)
    {
      reply(r, ss.str());
    }

    void reply(int r, const std::string &rs)
    {
      // Let the connection drop as soon as we've sent our response
      ConnectionRef con = m->get_connection();
      if (con) {
        con->mark_disposable();
      }

      if (r == 0) {
        dout(4) << __func__ << " success" << dendl;
      } else {
        derr << __func__ << " " << cpp_strerror(r) << " " << rs << dendl;
      }
      if (con) {
        MCommandReply *reply = new MCommandReply(r, rs);
        reply->set_tid(m->get_tid());
        reply->set_data(odata);
        con->send_message(reply);
      }
    }
  };

  /**
   * A context for receiving a bufferlist/error string from a background
   * function and then calling back to a CommandContext when it's done
   */
  class ReplyOnFinish : public Context {
    std::shared_ptr<CommandContext> cmdctx;

  public:
    bufferlist from_mon;
    string outs;

    ReplyOnFinish(std::shared_ptr<CommandContext> cmdctx_)
      : cmdctx(cmdctx_)
    {}
    void finish(int r) override {
      cmdctx->odata.claim_append(from_mon);
      cmdctx->reply(r, outs);
    }
  };

  std::shared_ptr<CommandContext> cmdctx = std::make_shared<CommandContext>(m);

  auto priv = m->get_connection()->get_priv();
  auto session = static_cast<MgrSession*>(priv.get());
  if (!session) {
    return true;
  }
  if (session->inst.name == entity_name_t())
    session->inst.name = m->get_source();

  std::string format;
  boost::scoped_ptr<Formatter> f;
  map<string,string> param_str_map;

  if (!cmdmap_from_json(m->cmd, &(cmdctx->cmdmap), ss)) {
    cmdctx->reply(-EINVAL, ss);
    return true;
  }

  {
    cmd_getval(g_ceph_context, cmdctx->cmdmap, "format", format, string("plain"));
    f.reset(Formatter::create(format));
  }

  cmd_getval(cct, cmdctx->cmdmap, "prefix", prefix);

  dout(4) << "decoded " << cmdctx->cmdmap.size() << dendl;
  dout(4) << "prefix=" << prefix << dendl;

  if (prefix == "get_command_descriptions") {
    dout(10) << "reading commands from python modules" << dendl;
    const auto py_commands = py_modules.get_commands();

    int cmdnum = 0;
    JSONFormatter f;
    f.open_object_section("command_descriptions");

    auto dump_cmd = [&cmdnum, &f](const MonCommand &mc){
      ostringstream secname;
      secname << "cmd" << setfill('0') << std::setw(3) << cmdnum;
      dump_cmddesc_to_json(&f, secname.str(), mc.cmdstring, mc.helpstring,
                           mc.module, mc.req_perms, mc.availability, 0);
      cmdnum++;
    };

    for (const auto &pyc : py_commands) {
      dump_cmd(pyc);
    }

    for (const auto &mgr_cmd : mgr_commands) {
      dump_cmd(mgr_cmd);
    }

    f.close_section();	// command_descriptions
    f.flush(cmdctx->odata);
    cmdctx->reply(0, ss);
    return true;
  }

  // lookup command
  const MonCommand *mgr_cmd = _get_mgrcommand(prefix, mgr_commands);
  _generate_command_map(cmdctx->cmdmap, param_str_map);

  bool is_allowed;
  bool cmd_is_rw = false;
  if (!mgr_cmd) {
    MonCommand py_command = {"", "", "py", "rw", "cli"};
    is_allowed = _allowed_command(session, py_command.module,
      prefix, cmdctx->cmdmap, param_str_map, &py_command);
  } else {
    // validate user's permissions for requested command
    is_allowed = _allowed_command(session, mgr_cmd->module,
      prefix, cmdctx->cmdmap,  param_str_map, mgr_cmd);
    cmd_is_rw = (mgr_cmd->requires_perm('w') || mgr_cmd->requires_perm('x'));
  }
  if (!is_allowed) {
    dout(1) << " access denied" << dendl;
    audit_clog->info() << "from='" << session->inst << "' "
                       << "entity='" << session->entity_name << "' "
                       << "cmd=" << m->cmd << ":  access denied";
    ss << "access denied' does your client key have mgr caps? "
          "See http://docs.ceph.com/docs/master/mgr/administrator/"
          "#client-authentication";
    cmdctx->reply(-EACCES, ss);
    return true;
  }

  dout(cmd_is_rw ? 0 : 5) << "from='" << session->inst << "' "
          << "entity='" << session->entity_name << "' "
          << "cmd=" << m->cmd << ": dispatch" << dendl;

  // ----------------
  // service map commands
  if (prefix == "service dump") {
    if (!f)
      f.reset(Formatter::create("json-pretty"));
    cluster_state.with_servicemap([&](const ServiceMap &service_map) {
	f->dump_object("service_map", service_map);
      });
    f->flush(cmdctx->odata);
    cmdctx->reply(0, ss);
    return true;
  }
  if (prefix == "service status") {
    if (!f)
      f.reset(Formatter::create("json-pretty"));
    // only include state from services that are in the persisted service map
    f->open_object_section("service_status");
    for (auto& p : pending_service_map.services) {
      f->open_object_section(p.first.c_str());
      for (auto& q : p.second.daemons) {
	f->open_object_section(q.first.c_str());
	DaemonKey key(p.first, q.first);
	assert(daemon_state.exists(key));
	auto daemon = daemon_state.get(key);
	Mutex::Locker l(daemon->lock);
	f->dump_stream("status_stamp") << daemon->service_status_stamp;
	f->dump_stream("last_beacon") << daemon->last_service_beacon;
	f->open_object_section("status");
	for (auto& r : daemon->service_status) {
	  f->dump_string(r.first.c_str(), r.second);
	}
	f->close_section();
	f->close_section();
      }
      f->close_section();
    }
    f->close_section();
    f->flush(cmdctx->odata);
    cmdctx->reply(0, ss);
    return true;
  }

  if (prefix == "config set") {
    std::string key;
    std::string val;
    cmd_getval(cct, cmdctx->cmdmap, "key", key);
    cmd_getval(cct, cmdctx->cmdmap, "value", val);
    r = cct->_conf->set_val(key, val, true, &ss);
    if (r == 0) {
      cct->_conf->apply_changes(nullptr);
    }
    cmdctx->reply(0, ss);
    return true;
  }

  // -----------
  // PG commands

  if (prefix == "pg scrub" ||
      prefix == "pg repair" ||
      prefix == "pg deep-scrub") {
    string scrubop = prefix.substr(3, string::npos);
    pg_t pgid;
    string pgidstr;
    cmd_getval(g_ceph_context, cmdctx->cmdmap, "pgid", pgidstr);
    if (!pgid.parse(pgidstr.c_str())) {
      ss << "invalid pgid '" << pgidstr << "'";
      cmdctx->reply(-EINVAL, ss);
      return true;
    }
    bool pg_exists = false;
    cluster_state.with_osdmap([&](const OSDMap& osdmap) {
	pg_exists = osdmap.pg_exists(pgid);
      });
    if (!pg_exists) {
      ss << "pg " << pgid << " dne";
      cmdctx->reply(-ENOENT, ss);
      return true;
    }
    int acting_primary = -1;
    cluster_state.with_osdmap([&](const OSDMap& osdmap) {
	acting_primary = osdmap.get_pg_acting_primary(pgid);
      });
    if (acting_primary == -1) {
      ss << "pg " << pgid << " has no primary osd";
      cmdctx->reply(-EAGAIN, ss);
      return true;
    }
    auto p = osd_cons.find(acting_primary);
    if (p == osd_cons.end()) {
      ss << "pg " << pgid << " primary osd." << acting_primary
	 << " is not currently connected";
      cmdctx->reply(-EAGAIN, ss);
      return true;
    }
    vector<pg_t> pgs = { pgid };
    for (auto& con : p->second) {
      con->send_message(new MOSDScrub(monc->get_fsid(),
				      pgs,
				      scrubop == "repair",
				      scrubop == "deep-scrub"));
    }
    ss << "instructing pg " << pgid << " on osd." << acting_primary
       << " to " << scrubop;
    cmdctx->reply(0, ss);
    return true;
  } else if (prefix == "osd scrub" ||
	      prefix == "osd deep-scrub" ||
	      prefix == "osd repair") {
    string whostr;
    cmd_getval(g_ceph_context, cmdctx->cmdmap, "who", whostr);
    vector<string> pvec;
    get_str_vec(prefix, pvec);

    set<int> osds;
    if (whostr == "*" || whostr == "all" || whostr == "any") {
      cluster_state.with_osdmap([&](const OSDMap& osdmap) {
	  for (int i = 0; i < osdmap.get_max_osd(); i++)
	    if (osdmap.is_up(i)) {
	      osds.insert(i);
	    }
	});
    } else {
      long osd = parse_osd_id(whostr.c_str(), &ss);
      if (osd < 0) {
	ss << "invalid osd '" << whostr << "'";
	cmdctx->reply(-EINVAL, ss);
	return true;
      }
      cluster_state.with_osdmap([&](const OSDMap& osdmap) {
	  if (osdmap.is_up(osd)) {
	    osds.insert(osd);
	  }
	});
      if (osds.empty()) {
	ss << "osd." << osd << " is not up";
	cmdctx->reply(-EAGAIN, ss);
	return true;
      }
    }
    set<int> sent_osds, failed_osds;
    for (auto osd : osds) {
      auto p = osd_cons.find(osd);
      if (p == osd_cons.end()) {
	failed_osds.insert(osd);
      } else {
	sent_osds.insert(osd);
	for (auto& con : p->second) {
	  con->send_message(new MOSDScrub(monc->get_fsid(),
					  pvec.back() == "repair",
					  pvec.back() == "deep-scrub"));
	}
      }
    }
    if (failed_osds.size() == osds.size()) {
      ss << "failed to instruct osd(s) " << osds << " to " << pvec.back()
	 << " (not connected)";
      r = -EAGAIN;
    } else {
      ss << "instructed osd(s) " << sent_osds << " to " << pvec.back();
      if (!failed_osds.empty()) {
	ss << "; osd(s) " << failed_osds << " were not connected";
      }
      r = 0;
    }
    cmdctx->reply(0, ss);
    return true;
  } else if (prefix == "osd reweight-by-pg" ||
	     prefix == "osd reweight-by-utilization" ||
	     prefix == "osd test-reweight-by-pg" ||
	     prefix == "osd test-reweight-by-utilization") {
    bool by_pg =
      prefix == "osd reweight-by-pg" || prefix == "osd test-reweight-by-pg";
    bool dry_run =
      prefix == "osd test-reweight-by-pg" ||
      prefix == "osd test-reweight-by-utilization";
    int64_t oload;
    cmd_getval(g_ceph_context, cmdctx->cmdmap, "oload", oload, int64_t(120));
    set<int64_t> pools;
    vector<string> poolnames;
    cmd_getval(g_ceph_context, cmdctx->cmdmap, "pools", poolnames);
    cluster_state.with_osdmap([&](const OSDMap& osdmap) {
	for (const auto& poolname : poolnames) {
	  int64_t pool = osdmap.lookup_pg_pool_name(poolname);
	  if (pool < 0) {
	    ss << "pool '" << poolname << "' does not exist";
	    r = -ENOENT;
	  }
	  pools.insert(pool);
	}
      });
    if (r) {
      cmdctx->reply(r, ss);
      return true;
    }
    double max_change = g_conf->mon_reweight_max_change;
    cmd_getval(g_ceph_context, cmdctx->cmdmap, "max_change", max_change);
    if (max_change <= 0.0) {
      ss << "max_change " << max_change << " must be positive";
      cmdctx->reply(-EINVAL, ss);
      return true;
    }
    int64_t max_osds = g_conf->mon_reweight_max_osds;
    cmd_getval(g_ceph_context, cmdctx->cmdmap, "max_osds", max_osds);
    if (max_osds <= 0) {
      ss << "max_osds " << max_osds << " must be positive";
      cmdctx->reply(-EINVAL, ss);
      return true;
    }
    string no_increasing;
    cmd_getval(g_ceph_context, cmdctx->cmdmap, "no_increasing", no_increasing);
    string out_str;
    mempool::osdmap::map<int32_t, uint32_t> new_weights;
    r = cluster_state.with_pgmap([&](const PGMap& pgmap) {
	return cluster_state.with_osdmap([&](const OSDMap& osdmap) {
	    return reweight::by_utilization(osdmap, pgmap,
					    oload,
					    max_change,
					    max_osds,
					    by_pg,
					    pools.empty() ? NULL : &pools,
					    no_increasing == "--no-increasing",
					    &new_weights,
					    &ss, &out_str, f.get());
	  });
      });
    if (r >= 0) {
      dout(10) << "reweight::by_utilization: finished with " << out_str << dendl;
    }
    if (f) {
      f->flush(cmdctx->odata);
    } else {
      cmdctx->odata.append(out_str);
    }
    if (r < 0) {
      ss << "FAILED reweight-by-pg";
      cmdctx->reply(r, ss);
      return true;
    } else if (r == 0 || dry_run) {
      ss << "no change";
      cmdctx->reply(r, ss);
      return true;
    } else {
      json_spirit::Object json_object;
      for (const auto& osd_weight : new_weights) {
	json_spirit::Config::add(json_object,
				 std::to_string(osd_weight.first),
				 std::to_string(osd_weight.second));
      }
      string s = json_spirit::write(json_object);
      std::replace(begin(s), end(s), '\"', '\'');
      const string cmd =
	"{"
	"\"prefix\": \"osd reweightn\", "
	"\"weights\": \"" + s + "\""
	"}";
      auto on_finish = new ReplyOnFinish(cmdctx);
      monc->start_mon_command({cmd}, {},
			      &on_finish->from_mon, &on_finish->outs, on_finish);
      return true;
    }
  } else if (prefix == "osd df") {
    string method;
    cmd_getval(g_ceph_context, cmdctx->cmdmap, "output_method", method);
    r = cluster_state.with_pgservice([&](const PGMapStatService& pgservice) {
	return cluster_state.with_osdmap([&](const OSDMap& osdmap) {
	    print_osd_utilization(osdmap, &pgservice, ss,
				  f.get(), method == "tree");
				  
	    cmdctx->odata.append(ss);
	    return 0;
	  });
      });
    cmdctx->reply(r, "");
    return true;
  } else if (prefix == "osd safe-to-destroy") {
    vector<string> ids;
    cmd_getval(g_ceph_context, cmdctx->cmdmap, "ids", ids);
    set<int> osds;
    int r;
    cluster_state.with_osdmap([&](const OSDMap& osdmap) {
	r = osdmap.parse_osd_id_list(ids, &osds, &ss);
      });
    if (!r && osds.empty()) {
      ss << "must specify one or more OSDs";
      r = -EINVAL;
    }
    if (r < 0) {
      cmdctx->reply(r, ss);
      return true;
    }
    set<int> active_osds, missing_stats, stored_pgs, safe_to_destroy;
    int affected_pgs = 0;
    cluster_state.with_pgmap([&](const PGMap& pg_map) {
	if (pg_map.num_pg_unknown > 0) {
	  ss << pg_map.num_pg_unknown << " pgs have unknown state; cannot draw"
	     << " any conclusions";
	  r = -EAGAIN;
	  return;
	}
	int num_active_clean = 0;
	for (auto& p : pg_map.num_pg_by_state) {
	  unsigned want = PG_STATE_ACTIVE|PG_STATE_CLEAN;
	  if ((p.first & want) == want) {
	    num_active_clean += p.second;
	  }
	}
	cluster_state.with_osdmap([&](const OSDMap& osdmap) {
	    for (auto osd : osds) {
	      if (!osdmap.exists(osd)) {
                safe_to_destroy.insert(osd);
		continue;  // clearly safe to destroy
	      }
	      auto q = pg_map.num_pg_by_osd.find(osd);
	      if (q != pg_map.num_pg_by_osd.end()) {
		if (q->second.acting > 0 || q->second.up > 0) {
		  active_osds.insert(osd);
		  affected_pgs += q->second.acting + q->second.up;
		  continue;
		}
	      }
	      if (num_active_clean < pg_map.num_pg) {
		// all pgs aren't active+clean; we need to be careful.
		auto p = pg_map.osd_stat.find(osd);
		if (p == pg_map.osd_stat.end() || !osdmap.is_up(osd)) {
		  missing_stats.insert(osd);
                  continue;
		} else if (p->second.num_pgs > 0) {
		  stored_pgs.insert(osd);
                  continue;
		}
	      }
              safe_to_destroy.insert(osd);
	    }
	  });
      });
    if (r && prefix == "osd safe-to-destroy") {
      cmdctx->reply(r, ss); // regardless of formatter
      return true;
    }
    if (!r && (!active_osds.empty() ||
               !missing_stats.empty() || !stored_pgs.empty())) {
       if (!safe_to_destroy.empty()) {
         ss << "OSD(s) " << safe_to_destroy
            << " are safe to destroy without reducing data durability. ";
       }
       if (!active_osds.empty()) {
         ss << "OSD(s) " << active_osds << " have " << affected_pgs
            << " pgs currently mapped to them. ";
       }
       if (!missing_stats.empty()) {
         ss << "OSD(s) " << missing_stats << " have no reported stats, and not all"
            << " PGs are active+clean; we cannot draw any conclusions. ";
       }
       if (!stored_pgs.empty()) {
         ss << "OSD(s) " << stored_pgs << " last reported they still store some PG"
            << " data, and not all PGs are active+clean; we cannot be sure they"
            << " aren't still needed.";
       }
       if (!active_osds.empty() || !stored_pgs.empty()) {
         r = -EBUSY;
       } else {
         r = -EAGAIN;
       }
    }
    if (!r) {
      ss << "OSD(s) " << osds << " are safe to destroy without reducing data"
         << " durability.";
      safe_to_destroy.swap(osds);
    }
    if (f) {
      f->open_object_section("osd_status");
      f->open_array_section("safe_to_destroy");
      for (auto i : safe_to_destroy)
        f->dump_int("osd", i);
      f->close_section();
      f->open_array_section("active");
      for (auto i : active_osds)
        f->dump_int("osd", i);
      f->close_section();
      f->open_array_section("missing_stats");
      for (auto i : missing_stats)
        f->dump_int("osd", i);
      f->close_section();
      f->open_array_section("stored_pgs");
      for (auto i : stored_pgs)
        f->dump_int("osd", i);
      f->close_section();
      f->close_section(); // osd_status
      f->flush(cmdctx->odata);
      r = 0;
      ss.clear();
      ss.str("");
    }
    cmdctx->reply(r, ss);
    return true;
  } else if (prefix == "osd ok-to-stop") {
    vector<string> ids;
    cmd_getval(g_ceph_context, cmdctx->cmdmap, "ids", ids);
    set<int> osds;
    int r;
    cluster_state.with_osdmap([&](const OSDMap& osdmap) {
	r = osdmap.parse_osd_id_list(ids, &osds, &ss);
      });
    if (!r && osds.empty()) {
      ss << "must specify one or more OSDs";
      r = -EINVAL;
    }
    if (r < 0) {
      cmdctx->reply(r, ss);
      return true;
    }
    map<pg_t,int> pg_delta;  // pgid -> net acting set size change
    int dangerous_pgs = 0;
    cluster_state.with_pgmap([&](const PGMap& pg_map) {
	return cluster_state.with_osdmap([&](const OSDMap& osdmap) {
	    if (pg_map.num_pg_unknown > 0) {
	      ss << pg_map.num_pg_unknown << " pgs have unknown state; "
		 << "cannot draw any conclusions";
	      r = -EAGAIN;
	      return;
	    }
	    for (auto osd : osds) {
	      auto p = pg_map.pg_by_osd.find(osd);
	      if (p != pg_map.pg_by_osd.end()) {
		for (auto& pgid : p->second) {
		  --pg_delta[pgid];
		}
	      }
	    }
	    for (auto& p : pg_delta) {
	      auto q = pg_map.pg_stat.find(p.first);
	      if (q == pg_map.pg_stat.end()) {
		ss << "missing information about " << p.first << "; cannot draw"
		   << " any conclusions";
		r = -EAGAIN;
		return;
	      }
	      if (!(q->second.state & PG_STATE_ACTIVE) ||
		  (q->second.state & PG_STATE_DEGRADED)) {
		// we don't currently have a good way to tell *how* degraded
		// a degraded PG is, so we have to assume we cannot remove
		// any more replicas/shards.
		++dangerous_pgs;
		continue;
	      }
	      const pg_pool_t *pi = osdmap.get_pg_pool(p.first.pool());
	      if (!pi) {
		++dangerous_pgs; // pool is creating or deleting
	      } else {
		if (q->second.acting.size() + p.second < pi->min_size) {
		  ++dangerous_pgs;
		}
	      }
	    }
	  });
      });
    if (r) {
      cmdctx->reply(r, ss);
      return true;
    }
    if (dangerous_pgs) {
      ss << dangerous_pgs << " PGs are already degraded or might become "
	 << "unavailable";
      cmdctx->reply(-EBUSY, ss);
      return true;
    }
    ss << "OSD(s) " << osds << " are ok to stop without reducing"
       << " availability, provided there are no other concurrent failures"
       << " or interventions. " << pg_delta.size() << " PGs are likely to be"
       << " degraded (but remain available) as a result.";
    cmdctx->reply(0, ss);
    return true;
  } else if (prefix == "pg force-recovery" ||
  	       prefix == "pg force-backfill" ||
  	       prefix == "pg cancel-force-recovery" ||
  	       prefix == "pg cancel-force-backfill") {
    string forceop = prefix.substr(3, string::npos);
    list<pg_t> parsed_pgs;
    map<int, list<pg_t> > osdpgs;

    // figure out actual op just once
    int actual_op = 0;
    if (forceop == "force-recovery") {
      actual_op = OFR_RECOVERY;
    } else if (forceop == "force-backfill") {
      actual_op = OFR_BACKFILL;
    } else if (forceop == "cancel-force-backfill") {
      actual_op = OFR_BACKFILL | OFR_CANCEL;
    } else if (forceop == "cancel-force-recovery") {
      actual_op = OFR_RECOVERY | OFR_CANCEL;
    }

    // covnert pg names to pgs, discard any invalid ones while at it
    {
      // we don't want to keep pgidstr and pgidstr_nodup forever
      vector<string> pgidstr;
      // get pgids to process and prune duplicates
      cmd_getval(g_ceph_context, cmdctx->cmdmap, "pgid", pgidstr);
      set<string> pgidstr_nodup(pgidstr.begin(), pgidstr.end());
      if (pgidstr.size() != pgidstr_nodup.size()) {
	// move elements only when there were duplicates, as this
	// reorders them
	pgidstr.resize(pgidstr_nodup.size());
	auto it = pgidstr_nodup.begin();
	for (size_t i = 0 ; i < pgidstr_nodup.size(); i++) {
	  pgidstr[i] = std::move(*it++);
	}
      }

      cluster_state.with_pgmap([&](const PGMap& pg_map) {
	for (auto& pstr : pgidstr) {
	  pg_t parsed_pg;
	  if (!parsed_pg.parse(pstr.c_str())) {
	    ss << "invalid pgid '" << pstr << "'; ";
	    r = -EINVAL;
	  } else {
	    auto workit = pg_map.pg_stat.find(parsed_pg);
	    if (workit == pg_map.pg_stat.end()) {
	      ss << "pg " << pstr << " does not exist; ";
	      r = -ENOENT;
	    } else {
	      pg_stat_t workpg = workit->second;

	      // discard pgs for which user requests are pointless
	      switch (actual_op)
	      {
		case OFR_RECOVERY:
		  if ((workpg.state & (PG_STATE_DEGRADED | PG_STATE_RECOVERY_WAIT | PG_STATE_RECOVERING)) == 0) {
		    // don't return error, user script may be racing with cluster. not fatal.
		    ss << "pg " << pstr << " doesn't require recovery; ";
		    continue;
		  } else  if (workpg.state & PG_STATE_FORCED_RECOVERY) {
		    ss << "pg " << pstr << " recovery already forced; ";
		    // return error, as it may be a bug in user script
		    r = -EINVAL;
		    continue;
		  }
		  break;
		case OFR_BACKFILL:
		  if ((workpg.state & (PG_STATE_DEGRADED | PG_STATE_BACKFILL_WAIT | PG_STATE_BACKFILLING)) == 0) {
		    ss << "pg " << pstr << " doesn't require backfilling; ";
		    continue;
		  } else  if (workpg.state & PG_STATE_FORCED_BACKFILL) {
		    ss << "pg " << pstr << " backfill already forced; ";
		    r = -EINVAL;
		    continue;
		  }
		  break;
		case OFR_BACKFILL | OFR_CANCEL:
		  if ((workpg.state & PG_STATE_FORCED_BACKFILL) == 0) {
		    ss << "pg " << pstr << " backfill not forced; ";
		    continue;
		  }
		  break;
		case OFR_RECOVERY | OFR_CANCEL:
		  if ((workpg.state & PG_STATE_FORCED_RECOVERY) == 0) {
		    ss << "pg " << pstr << " recovery not forced; ";
		    continue;
		  }
		  break;
		default:
		  assert(0 == "actual_op value is not supported");
	      }

	      parsed_pgs.push_back(std::move(parsed_pg));
	    }
	  }
	}

	// group pgs to process by osd
	for (auto& pgid : parsed_pgs) {
	  auto workit = pg_map.pg_stat.find(pgid);
	  if (workit != pg_map.pg_stat.end()) {
	    pg_stat_t workpg = workit->second;
	    set<int32_t> osds(workpg.up.begin(), workpg.up.end());
	    osds.insert(workpg.acting.begin(), workpg.acting.end());
	    for (auto i : osds) {
	      osdpgs[i].push_back(pgid);
	    }
	  }
	}

      });
    }

    // respond with error only when no pgs are correct
    // yes, in case of mixed errors, only the last one will be emitted,
    // but the message presented will be fine
    if (parsed_pgs.size() != 0) {
      // clear error to not confuse users/scripts
      r = 0;
    }

    // optimize the command -> messages conversion, use only one message per distinct OSD
    cluster_state.with_osdmap([&](const OSDMap& osdmap) {
      for (auto& i : osdpgs) {
	if (osdmap.is_up(i.first)) {
	  vector<pg_t> pgvec(make_move_iterator(i.second.begin()), make_move_iterator(i.second.end()));
	  auto p = osd_cons.find(i.first);
	  if (p == osd_cons.end()) {
	    ss << "osd." << i.first << " is not currently connected";
	    r = -EAGAIN;
	    continue;
	  }
	  for (auto& con : p->second) {
	    con->send_message(new MOSDForceRecovery(monc->get_fsid(), pgvec, actual_op));
	  }
	  ss << "instructing pg(s) " << i.second << " on osd." << i.first << " to " << forceop << "; ";
	}
      }
    });
    ss << std::endl;
    cmdctx->reply(r, ss);
  } else if (prefix == "mgr report imgs_perf") {
    string name, id;
    cmd_getval(g_ceph_context, cmdctx->cmdmap, "name", name);
    cmd_getval(g_ceph_context, cmdctx->cmdmap, "id", id);
    if (id.empty()) {
      r = -EINVAL;
      ss << "image id unspecified";
      cmdctx->reply(r, ss);
      return true;
    }

    bufferlist data(m->get_data());
    op_stat_t opstat;
    try {
      bufferlist::iterator bl(data.begin());
      opstat.decode(bl);
    } catch (const std::exception &e) {
      r = -EINVAL;
      ss << "Failed to parse report optstat: " << e.what();
      cmdctx->reply(r, ss);
      return true;
    }

    auto it = imgsmap.find(id);
    if (it != imgsmap.end()) {
      it->second.update_stat(opstat);
    } else {
      imgsmap.emplace(id, imageperf_t(name, opstat));
    }

    cmdctx->reply(0, "");
    return true;
  } else if (prefix == "mgr dump imgs_perf") {
    set<string> what;
    vector<string> dumpcontents;
    if (cmd_getval(g_ceph_context, cmdctx->cmdmap, "dumpcontents", dumpcontents)) {
        copy(dumpcontents.begin(), dumpcontents.end(),
           inserter(what, what.end()));
    }
    if (what.empty()) {
      what.insert("all");
    }

    if (f) {
      dump_imgsperf(f.get(), what);
      f->flush(cmdctx->odata);
    } else {
      stringstream dumps;
      ss << "dumping: " << what;
      dump_imgsperf(dumps, what);
      cmdctx->odata.append(dumps);
    }
    cmdctx->reply(0, "");
    return true;
  } else {
    r = cluster_state.with_pgmap([&](const PGMap& pg_map) {
	return cluster_state.with_osdmap([&](const OSDMap& osdmap) {
	    return process_pg_map_command(prefix, cmdctx->cmdmap, pg_map, osdmap,
					  f.get(), &ss, &cmdctx->odata);
	  });
      });

    if (r != -EOPNOTSUPP) {
      cmdctx->reply(r, ss);
      return true;
    }
  }

  // None of the special native commands, 
  ActivePyModule *handler = nullptr;
  auto py_commands = py_modules.get_py_commands();
  for (const auto &pyc : py_commands) {
    auto pyc_prefix = cmddesc_get_prefix(pyc.cmdstring);
    dout(1) << "pyc_prefix: '" << pyc_prefix << "'" << dendl;
    if (pyc_prefix == prefix) {
      handler = pyc.handler;
      break;
    }
  }

  if (handler == nullptr) {
    ss << "No handler found for '" << prefix << "'";
    dout(4) << "No handler found for '" << prefix << "'" << dendl;
    cmdctx->reply(-EINVAL, ss);
    return true;
  } else {
    // Okay, now we have a handler to call, but we must not call it
    // in this thread, because the python handlers can do anything,
    // including blocking, and including calling back into mgr.
    dout(4) << "passing through " << cmdctx->cmdmap.size() << dendl;
    finisher.queue(new FunctionContext([cmdctx, handler](int r_) {
      std::stringstream ds;
      std::stringstream ss;
      int r = handler->handle_command(cmdctx->cmdmap, &ds, &ss);
      cmdctx->odata.append(ds);
      cmdctx->reply(r, ss);
    }));
    return true;
  }
}

void DaemonServer::_prune_pending_service_map()
{
  utime_t cutoff = ceph_clock_now();
  cutoff -= g_conf->get_val<double>("mgr_service_beacon_grace");
  auto p = pending_service_map.services.begin();
  while (p != pending_service_map.services.end()) {
    auto q = p->second.daemons.begin();
    while (q != p->second.daemons.end()) {
      DaemonKey key(p->first, q->first);
      if (!daemon_state.exists(key)) {
	derr << "missing key " << key << dendl;
	++q;
	continue;
      }
      auto daemon = daemon_state.get(key);
      Mutex::Locker l(daemon->lock);
      if (daemon->last_service_beacon == utime_t()) {
	// we must have just restarted; assume they are alive now.
	daemon->last_service_beacon = ceph_clock_now();
	++q;
	continue;
      }
      if (daemon->last_service_beacon < cutoff) {
	dout(10) << "pruning stale " << p->first << "." << q->first
		 << " last_beacon " << daemon->last_service_beacon << dendl;
	q = p->second.daemons.erase(q);
	pending_service_map_dirty = pending_service_map.epoch;
      } else {
	++q;
      }
    }
    if (p->second.daemons.empty()) {
      p = pending_service_map.services.erase(p);
      pending_service_map_dirty = pending_service_map.epoch;
    } else {
      ++p;
    }
  }
}

void DaemonServer::send_report()
{
  if (!pgmap_ready) {
    if (ceph_clock_now() - started_at > g_conf->get_val<int64_t>("mgr_stats_period") * 4.0) {
      pgmap_ready = true;
      reported_osds.clear();
      dout(1) << "Giving up on OSDs that haven't reported yet, sending "
              << "potentially incomplete PG state to mon" << dendl;
    } else {
      dout(1) << "Not sending PG status to monitor yet, waiting for OSDs"
              << dendl;
      return;
    }
  }

  auto m = new MMonMgrReport();
  py_modules.get_health_checks(&m->health_checks);

  cluster_state.with_pgmap([&](const PGMap& pg_map) {
      cluster_state.try_mark_pg_stale();
      cluster_state.update_delta_stats();

      if (pending_service_map.epoch) {
	_prune_pending_service_map();
	if (pending_service_map_dirty >= pending_service_map.epoch) {
	  pending_service_map.modified = ceph_clock_now();
	  ::encode(pending_service_map, m->service_map_bl, CEPH_FEATURES_ALL);
	  dout(10) << "sending service_map e" << pending_service_map.epoch
		   << dendl;
	  pending_service_map.epoch++;
	}
      }

      cluster_state.with_osdmap([&](const OSDMap& osdmap) {
	  // FIXME: no easy way to get mon features here.  this will do for
	  // now, though, as long as we don't make a backward-incompat change.
	  pg_map.encode_digest(osdmap, m->get_data(), CEPH_FEATURES_ALL);
	  dout(10) << pg_map << dendl;

	  pg_map.get_health_checks(g_ceph_context, osdmap,
				   &m->health_checks);

	  dout(10) << m->health_checks.checks.size() << " health checks"
		   << dendl;
	  dout(20) << "health checks:\n";
	  JSONFormatter jf(true);
	  jf.dump_object("health_checks", m->health_checks);
	  jf.flush(*_dout);
	  *_dout << dendl;
          if (osdmap.require_osd_release >= CEPH_RELEASE_LUMINOUS) {
              clog->debug() << "pgmap v" << pg_map.version << ": " << pg_map;
          }
	});
    });

  auto osds = daemon_state.get_by_service("osd");
  map<osd_metric, unique_ptr<OSDHealthMetricCollector>> accumulated;
  for (const auto& osd : osds) {
    Mutex::Locker l(osd.second->lock);
    for (const auto& metric : osd.second->osd_health_metrics) {
      auto acc = accumulated.find(metric.get_type());
      if (acc == accumulated.end()) {
	auto collector = OSDHealthMetricCollector::create(metric.get_type());
	if (!collector) {
	  derr << __func__ << " " << osd.first << "." << osd.second
	       << " sent me an unknown health metric: "
	       << static_cast<uint8_t>(metric.get_type()) << dendl;
	  continue;
	}
	tie(acc, std::ignore) = accumulated.emplace(metric.get_type(),
						    std::move(collector));
      }
      acc->second->update(osd.first, metric);
    }
  }
  for (const auto& acc : accumulated) {
    acc.second->summarize(m->health_checks);
  }
  // TODO? We currently do not notify the PyModules
  // TODO: respect needs_send, so we send the report only if we are asked to do
  //       so, or the state is updated.
  monc->send_mon_message(m);
}

void DaemonServer::got_service_map()
{
  Mutex::Locker l(lock);

  cluster_state.with_servicemap([&](const ServiceMap& service_map) {
      if (pending_service_map.epoch == 0) {
	// we just started up
	dout(10) << "got initial map e" << service_map.epoch << dendl;
	pending_service_map = service_map;
      } else {
	// we we already active and therefore must have persisted it,
	// which means ours is the same or newer.
	dout(10) << "got updated map e" << service_map.epoch << dendl;
      }
      pending_service_map.epoch = service_map.epoch + 1;
    });

  // cull missing daemons, populate new ones
  for (auto& p : pending_service_map.services) {
    std::set<std::string> names;
    for (auto& q : p.second.daemons) {
      names.insert(q.first);
      DaemonKey key(p.first, q.first);
      if (!daemon_state.exists(key)) {
	auto daemon = std::make_shared<DaemonState>(daemon_state.types);
	daemon->key = key;
	daemon->metadata = q.second.metadata;
        if (q.second.metadata.count("hostname")) {
          daemon->hostname = q.second.metadata["hostname"];
        }
	daemon->service_daemon = true;
	daemon_state.insert(daemon);
	dout(10) << "added missing " << key << dendl;
      }
    }
    daemon_state.cull(p.first, names);
  }
}


const char** DaemonServer::get_tracked_conf_keys() const
{
  static const char *KEYS[] = {
    "mgr_stats_threshold",
    "mgr_stats_period",
    nullptr
  };

  return KEYS;
}

void DaemonServer::handle_conf_change(const struct md_config_t *conf,
                                              const std::set <std::string> &changed)
{
  dout(4) << "ohai" << dendl;

  if (changed.count("mgr_stats_threshold") || changed.count("mgr_stats_period")) {
    dout(4) << "Updating stats threshold/period on "
            << daemon_connections.size() << " clients" << dendl;
    // Send a fresh MMgrConfigure to all clients, so that they can follow
    // the new policy for transmitting stats
    finisher.queue(new FunctionContext([this](int r) {
      Mutex::Locker l(lock);
      for (auto &c : daemon_connections) {
        _send_configure(c);
      }
    }));
  }
}

void DaemonServer::_send_configure(ConnectionRef c)
{
  assert(lock.is_locked_by_me());

  auto configure = new MMgrConfigure();
  configure->stats_period = g_conf->get_val<int64_t>("mgr_stats_period");
  configure->stats_threshold = g_conf->get_val<int64_t>("mgr_stats_threshold");
  c->send_message(configure);
}

void DaemonServer::perf_stat_start() {
  Mutex::Locker l(lock);
  Context *callback = new FunctionContext([this](int r){ calc_perf(); });
  timer.add_event_after(
    g_ceph_context->_conf->get_val<int64_t>("mgr_image_perf_calc_interval"),
    callback);
}

void DaemonServer::calc_perf() {
  assert(lock.is_locked());

  utime_t now = ceph_clock_now();
  int64_t calc_interval = g_ceph_context->_conf->get_val<int64_t>("mgr_image_perf_calc_interval");
  int64_t clean_interval = g_ceph_context->_conf->get_val<int64_t>("mgr_image_perf_cleanup_interval");
  bool latency_us = g_ceph_context->_conf->get_val<bool>("mgr_op_latency_in_us");

  for (auto it = imgsmap.begin(); it != imgsmap.end(); /* empty */) {
    auto it2 = it++;
    if (now - it2->second.last_update > clean_interval) {
      imgsmap.erase(it2);
      continue;
    }

    it2->second.rd_ops = (it2->second.raw_data.rd_num - it2->second.pre_data.rd_num)/calc_interval;
    it2->second.rd_bws = (it2->second.raw_data.rd_bytes - it2->second.pre_data.rd_bytes)/calc_interval;
    it2->second.rd_lat = (double)(it2->second.raw_data.rd_latency - it2->second.pre_data.rd_latency)/
                         (it2->second.raw_data.rd_num - it2->second.pre_data.rd_num)/
                         (latency_us ? 1.0e3 : 1.0e6) + 0.5; // to microsecond or millisecond and round

    it2->second.wr_ops = (it2->second.raw_data.wr_num - it2->second.pre_data.wr_num)/calc_interval;
    it2->second.wr_bws = (it2->second.raw_data.wr_bytes - it2->second.pre_data.wr_bytes)/calc_interval;
    it2->second.wr_lat = (double)(it2->second.raw_data.wr_latency - it2->second.pre_data.wr_latency)/
                         (it2->second.raw_data.wr_num - it2->second.pre_data.wr_num)/
                         (latency_us ? 1.0e3 : 1.0e6) + 0.5;

    it2->second.total_ops = (it2->second.raw_data.op_num - it2->second.pre_data.op_num)/calc_interval;
    it2->second.total_bws = (it2->second.raw_data.op_bytes - it2->second.pre_data.op_bytes)/calc_interval;
    it2->second.total_lat = (double)(it2->second.raw_data.op_latency - it2->second.pre_data.op_latency)/
                            (it2->second.raw_data.op_num - it2->second.pre_data.op_num)/
                            (latency_us ? 1.0e3 : 1.0e6) + 0.5;

    it2->second.pre_data = it2->second.raw_data;
  }

  Context *callback = new FunctionContext([this](int r){ calc_perf(); });
    timer.add_event_after(calc_interval, callback);
}

void DaemonServer::dump_imgsperf(Formatter *f, set<string> &who) {
  f->open_object_section("image perf statistics");
  for (auto it = imgsmap.begin(); it != imgsmap.end(); it++) {
    if (!who.count("all") && !who.count(it->first)) {
      continue;
    }
    f->open_object_section(it->first.c_str());
    f->dump_string("name", it->second.imgname);
    f->dump_unsigned("ops", it->second.total_ops);
    f->dump_unsigned("ops_rd", it->second.rd_ops);
    f->dump_unsigned("ops_wr", it->second.wr_ops);
    f->dump_unsigned("thruput", it->second.total_bws);
    f->dump_unsigned("thruput_rd", it->second.rd_bws);
    f->dump_unsigned("thruput_wr", it->second.wr_bws);
    f->dump_unsigned("latency", it->second.total_lat);
    f->dump_unsigned("latency_rd", it->second.rd_lat);
    f->dump_unsigned("latency_wr", it->second.wr_lat);
    f->open_object_section("raw_data");
    f->dump_unsigned("op_num", it->second.raw_data.op_num);
    f->dump_unsigned("rd_num", it->second.raw_data.rd_num);
    f->dump_unsigned("wr_num", it->second.raw_data.wr_num);
    f->dump_unsigned("op_bytes", it->second.raw_data.op_bytes);
    f->dump_unsigned("rd_bytes", it->second.raw_data.rd_bytes);
    f->dump_unsigned("wr_bytes", it->second.raw_data.wr_bytes);
    f->dump_unsigned("op_latency", it->second.raw_data.op_latency);
    f->dump_unsigned("rd_latency", it->second.raw_data.rd_latency);
    f->dump_unsigned("wr_latency", it->second.raw_data.wr_latency);
    f->close_section();
    f->close_section();
  }
  f->close_section();
}

void DaemonServer::dump_imgsperf(ostream& ss, set<string> &who) {
  TextTable tab;
  uint32_t seqn = 0;

  tab.define_column("IMAGE_ID", TextTable::LEFT, TextTable::LEFT);
  tab.define_column("IOPS", TextTable::LEFT, TextTable::RIGHT);
  tab.define_column("IOPS_RD", TextTable::LEFT, TextTable::RIGHT);
  tab.define_column("IOPS_WR", TextTable::LEFT, TextTable::RIGHT);
  tab.define_column("|", TextTable::LEFT, TextTable::RIGHT);
  tab.define_column("THROUGHPUT", TextTable::LEFT, TextTable::RIGHT);
  tab.define_column("THRU_RD", TextTable::LEFT, TextTable::RIGHT);
  tab.define_column("THRU_WR", TextTable::LEFT, TextTable::RIGHT);
  tab.define_column("|", TextTable::LEFT, TextTable::RIGHT);
  tab.define_column("LATENCY", TextTable::LEFT, TextTable::RIGHT);
  tab.define_column("LAT_RD", TextTable::LEFT, TextTable::RIGHT);
  tab.define_column("LAT_WR", TextTable::LEFT, TextTable::RIGHT);
  tab.define_column("|", TextTable::LEFT, TextTable::RIGHT);
  tab.define_column("IMAGE_NAME", TextTable::LEFT, TextTable::LEFT);

  for (auto it = imgsmap.begin(); it != imgsmap.end(); it++) {
    if (!who.count("all") && !who.count(it->first)) {
      continue;
    }

    string imgname = std::to_string(++seqn) + " " + it->first;
    tab << imgname
        << it->second.total_ops
        << it->second.rd_ops
        << it->second.wr_ops
        << "|"
        << it->second.total_bws
        << it->second.rd_bws
        << it->second.wr_bws
        << "|"
        << it->second.total_lat
        << it->second.rd_lat
        << it->second.wr_lat
        << "|"
        << it->second.imgname
        << TextTable::endrow;
  }

  ss << tab;
}

void DaemonServer::dump_cluster_state(Formatter *f) {
  f->open_object_section("cluster state");
  cluster_state.dump(f);
  f->close_section();
}

void DaemonServer::send_reset_recovery_limits(
  int who,
  uint8_t options,
  double bandwidth_factor,
  double maxactive_factor,
  double aggressive_factor) {
  auto p = osd_cons.find(who);
  if (p == osd_cons.end()) {
    derr << "osd." << who << " is not currently connected" << dendl;
    return;
  }
  for (auto& con : p->second) {
    con->send_message(new MOSDResetRecoveryLimits(
      monc->get_fsid(),
      options,
      bandwidth_factor,
      maxactive_factor,
      aggressive_factor));
  }
  if ((options & OSD_RESET_RECOVERY_BANDWIDTH) ==
                 OSD_RESET_RECOVERY_BANDWIDTH)
    last_adjusted_osds.insert(who);
  if ((options & OSD_RESET_RECOVERY_MAXACTIVE) ==
                 OSD_RESET_RECOVERY_MAXACTIVE)
    last_adjusted_primaries.insert(who);
}

void DaemonServer::clear_recovery_limits()
{
  for (auto o : last_adjusted_osds) {
    uint8_t options = OSD_RESET_RECOVERY_BANDWIDTH;
    auto it = last_adjusted_primaries.find(o);
    if (it != last_adjusted_primaries.end()) {
      // clear both
      options |= OSD_RESET_RECOVERY_MAXACTIVE;
      dout(0) << "restore osd." << o << " recovery settings" << dendl;
    } else {
      dout(0) << "restore osd." << o << " bandwidth settings" << dendl;
    }
    send_reset_recovery_limits(o, options);
    if (it != last_adjusted_primaries.end()) {
      last_adjusted_primaries.erase(it);
    }
  }
  last_adjusted_osds.clear();
  for (auto p : last_adjusted_primaries) {
    dout(0) << "restore primary osd." << p << " max active settings" << dendl;
    send_reset_recovery_limits(p, OSD_RESET_RECOVERY_MAXACTIVE);
  }
  last_adjusted_primaries.clear();
}

void DaemonServer::maybe_reset_recovery_limits()
{
  bool all_active_clean = false;
  bool any_backfilling_pgs = false;
  map<int, int64_t> num_objects_to_recover_by_osd;
  map<int, int64_t> num_objects_to_recover_by_primary;
  auto now = ceph_clock_now();
  auto conf = g_ceph_context->_conf;
  auto interval = conf->get_val<int64_t>("mgr_recovery_balancer_adjust_interval");
  if (interval == 0 ||  // set 0 to disable adjustment
      now - last_adjust < interval) {
    return;
  }
  last_adjust = now;

  // collect pg backfilling info
  cluster_state.with_pgmap([&](const PGMap& pg_map) {
    int num_active_clean = 0;
    for (auto& p : pg_map.num_pg_by_state) {
      if ((p.first & PG_STATE_BACKFILLING) == PG_STATE_BACKFILLING)
        any_backfilling_pgs = true;
      if ((p.first & (PG_STATE_ACTIVE | PG_STATE_CLEAN)) ==
          (PG_STATE_ACTIVE | PG_STATE_CLEAN))
        num_active_clean += p.second;
    }
    if (num_active_clean == pg_map.num_pg)
      all_active_clean = true;
    if (!any_backfilling_pgs)
      return;
    for (auto &ps: pg_map.pg_stat) {
      auto stat = ps.second;
      if ((stat.state & PG_STATE_BACKFILLING) != PG_STATE_BACKFILLING)
        continue;
      auto num_objects_to_recover = std::max((int64_t)0, std::min(stat.stats.sum.num_objects,
        stat.stats.sum.num_objects_degraded + stat.stats.sum.num_objects_misplaced));

      if (!stat.acting.empty()) {
        auto acting_primary = *(stat.acting.begin());
        num_objects_to_recover_by_primary[acting_primary] += num_objects_to_recover;
      }
      for (auto u: stat.up) {
        if (std::find(stat.acting.begin(), stat.acting.end(), u) == stat.acting.end()) {
          num_objects_to_recover_by_osd[u] += num_objects_to_recover;
        }
      }
    }
  });

  if (all_active_clean) {
    dout(10) << "all PGs become active+clean again, do cleanup" << dendl;
    clear_recovery_limits();
    return;
  }

  if (!any_backfilling_pgs) {
    clear_recovery_limits();
    dout(10) << "no backfilling PGs, cancelling" << dendl;
    return;
  }

  auto min_objects = conf->get_val<int64_t>(
    "mgr_recovery_balancer_min_objects");
  if (min_objects < 0) {
    dout(10) << "disabled by setting min_objects to " << min_objects << dendl;
    clear_recovery_limits();
    return;
  }
  auto min_diff = conf->get_val<double>("mgr_recovery_balancer_min_diff");
  auto min_adjustment_factor = conf->get_val<double>(
    "mgr_recovery_balancer_min_adjustment_factor");
  auto max_adjustment_factor = conf->get_val<double>(
    "mgr_recovery_balancer_max_adjustment_factor");
  auto do_aggressive_adjustment = conf->get_val<bool>(
    "mgr_recovery_balancer_do_aggressive_adjustment");
  auto min_aggressive_osds = conf->get_val<int64_t>(
    "mgr_recovery_balancer_min_aggressive_osds");
  auto max_aggressive_adjustment_factor = conf->get_val<double>(
    "mgr_recovery_balancer_max_aggressive_adjustment_factor");

  do {
    // backfill_targets first
    auto it = num_objects_to_recover_by_osd.begin();
    while (it != num_objects_to_recover_by_osd.end()) {
      if (it->second < min_objects) {
        dout(10) << "osd." << it->first << " only has " << it->second
                 << " object(s) remaining to recover, which is < "
                 << min_objects << ", skipping"
                 << dendl;
        num_objects_to_recover_by_osd.erase(it++);
      } else {
        it++;
      }
    }

    int64_t osd_num = num_objects_to_recover_by_osd.size();
    if (osd_num == 0) {
      dout(10) << "all backfilling PGs are going to finish quickly,"
               << "cancelling"
               << dendl;
      return;
    } else if (osd_num <= min_aggressive_osds) {
      dout(10) << "only " << osd_num << " backfilling-in OSDs (which is <= "
               << min_aggressive_osds << "), will enable aggressive mode"
               << dendl;
      for (auto &o : num_objects_to_recover_by_osd) {
        auto who = o.first;
        dout(0) << "aggressively reset osd." << who << "'s "
                << "recovery bandwidth into " << max_adjustment_factor << "x"
                << ", and can be promoted to "
                << max_aggressive_adjustment_factor << "x when appropriate"
                << dendl;
        send_reset_recovery_limits(who,
                                   OSD_RESET_RECOVERY_BANDWIDTH,
                                   max_adjustment_factor,
                                   1, // leave max-active unchanged
                                   max_aggressive_adjustment_factor);
      }
      break; // continue to adjust primaries
    } else {
      dout(10) << "OSDs will do adjustment:"
               << num_objects_to_recover_by_osd
               << dendl;
    }

    int64_t total = 0;
    for (auto &o : num_objects_to_recover_by_osd) {
      total += o.second;
    }
    auto average = total / osd_num;
    if (average == 0)
      break;
    for (auto &o : num_objects_to_recover_by_osd) {
      auto who = o.first;
      auto factor = o.second / (double)average;
      auto diff = abs(1.0 - factor);
      if (diff < min_diff) {
        dout(10) << "osd." << who << " adjustment diff " << diff
                 << " < min_diff " << min_diff << ", skipping"
                 << dendl;
        continue;
      }
      factor = std::max(factor, min_adjustment_factor);
      factor = std::min(factor, max_adjustment_factor);
      dout(0) << "adjust osd." << who
              << "'s recovery bandwidth into " << factor << "x, "
              << o.second << "/" << average
              << dendl;
      send_reset_recovery_limits(who, OSD_RESET_RECOVERY_BANDWIDTH, factor);
    }
  } while (false);

  do {
    // adjust primaries too, if possible
    auto it = num_objects_to_recover_by_primary.begin();
    while (it != num_objects_to_recover_by_primary.end()) {
      if (it->second < min_objects) {
        dout(10) << "osd." << it->first << " only has " << it->second
                 << " object(s) remaining to recover, which is < "
                 << min_objects << ", skipping"
                 << dendl;
        num_objects_to_recover_by_primary.erase(it++);
      } else {
        it++;
      }
    }
    int64_t primary_num = num_objects_to_recover_by_primary.size();
    if (primary_num == 0) {
      dout(10) << "no primaries left to adjust"
               << dendl;
      return;
    } else if (primary_num <= min_aggressive_osds) {
      dout(10) << "only " << primary_num << " backfilling primaries "
               << "(which is <= " << min_aggressive_osds << "), "
               << "will enable aggressive mode"
               << dendl;
      for (auto &p : num_objects_to_recover_by_primary) {
        auto who = p.first;
        dout(0) << "aggressively reset primary osd." << who << "'s "
                << "osd_recovery_max_active into "
                << max_adjustment_factor << "x"
                << ", and can be promoted to "
                << max_aggressive_adjustment_factor << "x when appropriate"
                << dendl;
        send_reset_recovery_limits(who,
                                   OSD_RESET_RECOVERY_MAXACTIVE,
                                   1, // leave bandwidth unchanged
                                   max_adjustment_factor,
                                   max_aggressive_adjustment_factor);
      }
      return;
    } else {
      dout(10) << "Primaries will do adjustment:"
               << num_objects_to_recover_by_primary
               << dendl;
    }

    int64_t total = 0;
    int64_t min = INT64_MAX;
    for (auto &p : num_objects_to_recover_by_primary) {
      total += p.second;
      if (p.second < min)
        min = p.second;
    }
    auto average = total / primary_num;
    if (average == 0)
      break;
    assert(min > 0);
    for (auto &p : num_objects_to_recover_by_primary) {
      auto who = p.first;
      auto factor = p.second / (double)average;
      auto aggressive_factor = p.second / (double)min;
      if (p.second <= average) {
        dout(10) << "primary osd." << who << " has less objects " << p.second
                 << " < average " << average
                 << ", reset factor to 1x (no change)"
                 << dendl;
        factor = 1.0;
      } else {
        auto diff = factor - 1.0;
        if (diff < min_diff) {
          dout(10) << "primary osd." << who << " adjustment diff " << diff
                   << " < min_diff " << min_diff
                   << ", reset factor to 1x (no change)"
                   << dendl;
          factor = 1.0;
        }
      }
      factor = std::min(factor, max_adjustment_factor);
      aggressive_factor = std::min(aggressive_factor,
        max_aggressive_adjustment_factor);
      aggressive_factor = do_aggressive_adjustment ? aggressive_factor : 1;
      dout(0) << "adjust primary osd." << who
              << "'s osd_recovery_max_active into " << factor << "x"
              << ", and can be promoted to " << aggressive_factor << "x"
              << " when appropriate"
              << dendl;
      send_reset_recovery_limits(who,
                                 OSD_RESET_RECOVERY_MAXACTIVE,
                                 1,
                                 factor,
                                 aggressive_factor);
    }
  } while (false);
}

bool MgrDaemonHook::call(std::string command, cmdmap_t& cmdmap,
			 std::string format, bufferlist& out)
{
  Formatter *f = Formatter::create(
                 format, "json-pretty", "json-pretty");

  if (command == "dump_image_perf") {
    set<string> what;
    what.insert("all");
    m_server->dump_imgsperf(f, what);
  } else if (command == "dump_cluster_state") {
    m_server->dump_cluster_state(f);
  }

  f->flush(out);
  delete f;
  return true;
}
