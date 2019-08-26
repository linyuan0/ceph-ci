import re
import json
import time
import uuid
import errno
import traceback

from mgr_module import CommandResult

from datetime import datetime, timedelta
from threading import Lock, Condition, Thread

QUERY_IDS = "query_ids"
GLOBAL_QUERY_ID = "global_query_id"
QUERY_LAST_REQUEST = "last_time_stamp"
QUERY_RAW_COUNTERS = "query_raw_counters"
QUERY_RAW_COUNTERS_GLOBAL = "query_raw_counters_global"

MDS_RANK_ALL = (-1,)
CLIENT_ID_ALL = "\d*"
CLIENT_IP_ALL = ".*"

MDS_PERF_QUERY_REGEX_MATCH_ALL_RANKS = '^(.*)$'
MDS_PERF_QUERY_REGEX_MATCH_CLIENTS = '^(client.{0}\s+{1}):.*'
MDS_PERF_QUERY_COUNTERS = ['cap_hit']
MDS_GLOBAL_PERF_QUERY_COUNTERS = ['read_latency', 'write_latency', 'metadata_latency']

QUERY_EXPIRE_INTERVAL = timedelta(minutes=1)

CLIENT_METADATA_KEY = "client_metadata"
CLIENT_METADATA_SUBKEYS = ["hostname", "root"]
CLIENT_METADATA_SUBKEYS_OPTIONAL = ["mount_point"]

NON_EXISTENT_KEY_STR = "N/A"

class FilterSpec(object):
    """
    query filters encapsulated and used as key for query map
    """
    def __init__(self, mds_ranks, client_id, client_ip):
        self.mds_ranks = mds_ranks
        self.client_id = client_id
        self.client_ip = client_ip

    def __hash__(self):
        return hash((self.mds_ranks, self.client_id, self.client_ip))

    def __eq__(self, other):
        return (self.mds_ranks, self.client_id, self.client_ip) == (other.mds_ranks, other.client_id, self.client_ip)

    def __ne__(self, other):
        return not(self == other)

def extract_mds_ranks_from_spec(mds_rank_spec):
    if not mds_rank_spec:
        return MDS_RANK_ALL
    match = re.match(r'^(\d[,\d]*)$', mds_rank_spec)
    if not match:
        raise ValueError("invalid mds filter spec: {}".format(mds_rank_spec))
    return tuple(int(mds_rank) for mds_rank in match.group(0).split(','))

def extract_client_id_from_spec(client_id_spec):
    if not client_id_spec:
        return CLIENT_ID_ALL
    # the client id is the spec itself since it'll be a part
    # of client filter regex.
    return client_id_spec

def extract_client_ip_from_spec(client_ip_spec):
    if not client_ip_spec:
        return CLIENT_IP_ALL
    # TODO: validate if it is an ip address (or a subset of it).
    # the client ip is the spec itself since it'll be a part
    # of client filter regex.
    return client_ip_spec

def extract_mds_ranks_from_report(mds_ranks_str):
    if not mds_ranks_str:
        return []
    return [int(x) for x in mds_ranks_str.split(',')]

def extract_client_id_and_ip(client):
    match = re.match(r'^(client\.\d+)\s(.*)', client)
    if match:
        return match.group(1), match.group(2)
    return None, None

class FSPerfStats(object):
    lock = Lock()
    q_cv = Condition(lock)
    r_cv = Condition(lock)

    user_queries = {}

    meta_lock = Lock()
    client_metadata = {
        'metadata' : {},
        'to_purge' : set(),
        'in_progress' : {},
    }

    def __init__(self, module):
        self.module = module
        self.log = module.log
        # report processor thread
        self.report_processor = Thread(target=self.run)
        self.report_processor.start()

    def set_client_metadata(self, client_id, key, meta):
        result = self.client_metadata['metadata'].setdefault(client_id, {})
        if not key in result or not result[key] == meta:
            result[key] = meta

    def notify(self, cmdtag):
        self.log.debug("cmdtag={0}".format(cmdtag))
        with self.meta_lock:
            result = self.client_metadata['in_progress'].pop(cmdtag)
            client_meta = result[1].wait()
            if client_meta[0] != 0:
                self.log.warn("failed to fetch client metadata from rank {0}, err={1}".format(
                    result[0], client_meta[2]))
                return
            for metadata in json.loads(client_meta[1]):
                client_id = "client.{0}".format(metadata['id'])
                result = self.client_metadata['metadata'].setdefault(client_id, {})
                for subkey in CLIENT_METADATA_SUBKEYS:
                    self.set_client_metadata(client_id, subkey, metadata[CLIENT_METADATA_KEY][subkey])
                for subkey in CLIENT_METADATA_SUBKEYS_OPTIONAL:
                    self.set_client_metadata(client_id, subkey,
                                             metadata[CLIENT_METADATA_KEY].get(subkey, NON_EXISTENT_KEY_STR))
            # when all async requests are done, purge clients metadata if any.
            if not self.client_metadata['in_progress']:
                for client in self.client_metadata['to_purge']:
                    try:
                        self.log.info("purge client metadata for {0}".format(client))
                        self.client_metadata['metadata'].remove(client)
                    except:
                        pass
                self.client_metadata['to_purge'].clear()
            self.log.debug("client_metadata={0}, to_purge={1}".format(
                self.client_metadata['metadata'], self.client_metadata['to_purge']))

    def update_client_meta(self, rank_set):
        new_updates = {}
        pending_updates = [v[0] for v in self.client_metadata['in_progress'].values()]
        with self.meta_lock:
            for rank in rank_set:
                if rank in pending_updates:
                    continue
                tag = str(uuid.uuid4())
                result = CommandResult(tag)
                new_updates[tag] = (rank, result)
            self.client_metadata['in_progress'].update(new_updates)

        self.log.debug("updating client metadata from {0}".format(new_updates))

        cmd_dict = {'prefix': 'client ls'}
        for tag,val in new_updates.items():
            self.module.send_command(val[1], "mds", str(val[0]), json.dumps(cmd_dict), tag)

    def run(self):
        try:
            self.log.info("FSPerfStats::report_processor starting...")
            while True:
                with self.lock:
                    self.scrub_expired_queries()
                    self.process_mds_reports()
                    self.r_cv.notify()

                    stats_period = int(self.module.get_ceph_option("mgr_stats_period"))
                    self.q_cv.wait(stats_period)
                self.log.debug("FSPerfStats::tick")
        except Exception as e:
            self.log.fatal("fatal error: {}".format(traceback.format_exc()))

    def cull_mds_entries(self, raw_perf_counters, incoming_metrics, missing_clients):
        # this is pretty straight forward -- find what MDSs are missing from
        # what is tracked vs what we received in incoming report and purge
        # the whole bunch.
        tracked_ranks = raw_perf_counters.keys()
        available_ranks = [int(counter['k'][0][0]) for counter in incoming_metrics]
        for rank in set(tracked_ranks) - set(available_ranks):
            culled = raw_perf_counters.pop(rank)
            self.log.info("culled {0} client entries from rank {1} (laggy: {2})".format(
                len(culled[1]), rank, "yes" if culled[0] else "no"))
            missing_clients.update(list(culled[1].keys()))

    def cull_client_entries(self, raw_perf_counters, incoming_metrics, missing_clients):
        # this is a bit more involed -- for each rank figure out what clients
        # are missing in incoming report and purge them from our tracked map.
        # but, if this is invoked _after_ cull_mds_entries(), the rank set
        # is same, so we can loop based on that assumption.
        ranks = raw_perf_counters.keys()
        for rank in ranks:
            tracked_clients = raw_perf_counters[rank][1].keys()
            available_clients = [extract_client_id_and_ip(counter['k'][1][0]) for counter in incoming_metrics]
            for client in set(tracked_clients) - set([c[0] for c in available_clients if c[0] is not None]):
                raw_perf_counters[rank][1].pop(client)
                self.log.info("culled {0} from rank {1}".format(client, rank))
                missing_clients.add(client)

    def cull_missing_entries(self, raw_perf_counters, incoming_metrics):
        missing_clients = set()
        self.cull_mds_entries(raw_perf_counters, incoming_metrics, missing_clients)
        self.cull_client_entries(raw_perf_counters, incoming_metrics, missing_clients)

        self.log.debug("missing_clients={0}".format(missing_clients))
        with self.meta_lock:
            if self.client_metadata['in_progress']:
                self.client_metadata['to_purge'].update(missing_clients)
                self.log.info("deferring client metadata purge (now {0} client(s))".format(
                    len(self.client_metadata['to_purge'])))
            else:
                for client in missing_clients:
                    try:
                        self.log.info("purge client metadata for {0}".format(client))
                        self.client_metadata['metadata'].pop(client)
                    except KeyError:
                        pass
                self.log.debug("client_metadata={0}".format(self.client_metadata['metadata']))

    def cull_global_metrics(self, raw_perf_counters, incoming_metrics):
        tracked_clients = raw_perf_counters.keys()
        available_clients = [counter['k'][0][0] for counter in incoming_metrics]
        for client in set(tracked_clients) - set(available_clients):
            raw_perf_counters.pop(client)

    def get_raw_perf_counters(self, query):
        raw_perf_counters = query.setdefault(QUERY_RAW_COUNTERS, {})

        for query_id in query[QUERY_IDS]:
            result = self.module.get_mds_perf_counters(query_id)
            self.log.debug("raw_perf_counters={}".format(raw_perf_counters))
            self.log.debug("get_raw_perf_counters={}".format(result))

            # extract passed in delayed ranks. metrics for delayed ranks are tagged
            # as stale.
            delayed_ranks = extract_mds_ranks_from_report(result['metrics'][0][0])

            # what's received from MDS
            incoming_metrics = result['metrics'][1]

            # cull missing MDSs and clients
            self.cull_missing_entries(raw_perf_counters, incoming_metrics)

            # iterate over metrics list and update our copy (note that we have
            # already culled the differences).
            meta_refresh_ranks = set()
            for counter in incoming_metrics:
                mds_rank = int(counter['k'][0][0])
                client_id, client_ip = extract_client_id_and_ip(counter['k'][1][0])
                if client_id is not None or not client_ip: # client_id _could_ be 0
                    with self.meta_lock:
                        if not client_id in self.client_metadata['metadata']:
                            meta_refresh_ranks.add(mds_rank)
                        self.set_client_metadata(client_id, "IP", client_ip)
                else:
                    self.log.warn("client metadata for client_id={0} might be unavailable".format(client_id))

                raw_counters = raw_perf_counters.setdefault(mds_rank, [False, {}])
                raw_counters[0] = True if mds_rank in delayed_ranks else False
                raw_client_counters = raw_counters[1].setdefault(client_id, [])

                del raw_client_counters[:]
                raw_client_counters.extend(counter['c'])
        # send an asynchronous client metadata refresh
        self.update_client_meta(meta_refresh_ranks)

    def get_raw_perf_counters_global(self, query):
        raw_perf_counters = query.setdefault(QUERY_RAW_COUNTERS_GLOBAL, {})
        result = self.module.get_mds_perf_counters(query[GLOBAL_QUERY_ID])

        self.log.debug("raw_perf_counters_global={}".format(raw_perf_counters))
        self.log.debug("get_raw_perf_counters_global={}".format(result))

        global_metrics = result['metrics'][1]
        self.cull_global_metrics(raw_perf_counters, global_metrics)
        for counter in global_metrics:
            client_id, _ = extract_client_id_and_ip(counter['k'][0][0])
            raw_client_counters = raw_perf_counters.setdefault(client_id, [])
            del raw_client_counters[:]
            raw_client_counters.extend(counter['c'])

    def process_mds_reports(self):
        for query in self.user_queries.values():
            self.get_raw_perf_counters(query)
            self.get_raw_perf_counters_global(query)

    def scrub_expired_queries(self):
        expire_time = datetime.now() - QUERY_EXPIRE_INTERVAL
        for filter_spec in list(self.user_queries.keys()):
            user_query = self.user_queries[filter_spec]
            self.log.debug("query={}".format(user_query))
            if user_query[QUERY_LAST_REQUEST] < expire_time:
                expired_query_ids = user_query[QUERY_IDS].copy()
                expired_query_ids.append(user_query[GLOBAL_QUERY_ID])
                self.unregister_mds_perf_queries(filter_spec, expired_query_ids)
                del self.user_queries[filter_spec]

    def prepare_mds_perf_query(self, rank, client_id, client_ip):
        mds_rank_regex = MDS_PERF_QUERY_REGEX_MATCH_ALL_RANKS
        if not rank == -1:
            mds_rank_regex = '^({})$'.format(rank)
        client_regex = MDS_PERF_QUERY_REGEX_MATCH_CLIENTS.format(client_id, client_ip)
        return {
            'key_descriptor' : [
                {'type' : 'mds_rank', 'regex' : mds_rank_regex},
                {'type' : 'client_id', 'regex' : client_regex},
                ],
            'performance_counter_descriptors' : MDS_PERF_QUERY_COUNTERS,
            }

    def prepare_global_perf_query(self, client_id, client_ip):
        client_regex = MDS_PERF_QUERY_REGEX_MATCH_CLIENTS.format(client_id, client_ip)
        return {
            'key_descriptor' : [
                {'type' : 'client_id', 'regex' : client_regex},
                ],
            'performance_counter_descriptors' : MDS_GLOBAL_PERF_QUERY_COUNTERS,
            }

    def unregister_mds_perf_queries(self, filter_spec, query_ids):
        self.log.info("unregister_mds_perf_queries: filter_spec={0}, query_id={1}".format(
            filter_spec, query_ids))
        for query_id in query_ids:
            self.module.remove_mds_perf_query(query_id)

    def register_mds_perf_query(self, filter_spec):
        mds_ranks = filter_spec.mds_ranks
        client_id = filter_spec.client_id
        client_ip = filter_spec.client_ip

        query_ids = []
        try:
            # register per-mds perf query
            for rank in mds_ranks:
                query = self.prepare_mds_perf_query(rank, client_id, client_ip)
                self.log.info("register_mds_perf_query: {}".format(query))

                query_id = self.module.add_mds_perf_query(query)
                if query_id is None: # query id can be 0
                    raise RuntimeError("failed to add MDS perf query: {}".format(query))
                query_ids.append(query_id)
        except Exception:
            for query_id in query_ids:
                self.module.remove_mds_perf_query(query_id)
            raise
        return query_ids

    def register_global_perf_query(self, filter_spec):
        client_id = filter_spec.client_id
        client_ip = filter_spec.client_ip

        # register a global perf query for metrics
        query = self.prepare_global_perf_query(client_id, client_ip)
        self.log.info("register_global_perf_query: {}".format(query))

        query_id = self.module.add_mds_perf_query(query)
        if query_id is None: # query id can be 0
            raise RuntimeError("failed to add global perf query: {}".format(query))
        return query_id

    def register_query(self, filter_spec):
        user_query = self.user_queries.get(filter_spec, None)
        if not user_query:
            user_query = {
                QUERY_IDS : self.register_mds_perf_query(filter_spec),
                GLOBAL_QUERY_ID : self.register_global_perf_query(filter_spec),
                QUERY_LAST_REQUEST : datetime.now(),
                }
            self.user_queries[filter_spec] = user_query

            self.q_cv.notify()
            self.r_cv.wait(5)
        else:
            user_query[QUERY_LAST_REQUEST] = datetime.now()
        return user_query

    def generate_report(self, user_query):
        result = {}
        # start with counter info -- metrics that are global and per mds
        result["global_counters"] = MDS_GLOBAL_PERF_QUERY_COUNTERS
        result["counters"] = MDS_PERF_QUERY_COUNTERS

        # fill in client metadata
        raw_perfs = user_query.setdefault(QUERY_RAW_COUNTERS_GLOBAL, {})
        with self.meta_lock:
            result_meta = result.setdefault("client_metadata", {})
            for client_id in raw_perfs.keys():
                if client_id in self.client_metadata["metadata"]:
                    client_meta = result_meta.setdefault(client_id, {})
                    client_meta.update(self.client_metadata["metadata"][client_id])

        # start populating global perf metrics w/ client metadata
        metrics = result.setdefault("global_metrics", {})
        for client_id, counters in raw_perfs.items():
            global_client_metrics = metrics.setdefault(client_id, [])
            del global_client_metrics[:]
            global_client_metrics.extend(counters)

        # and, now per-mds metrics keyed by mds rank along with delayed ranks
        raw_perfs = user_query.setdefault(QUERY_RAW_COUNTERS, {})
        metrics = result.setdefault("metrics", {})

        metrics["delayed_ranks"] = [rank for rank,counters in raw_perfs.items() if counters[0]]
        for rank, counters in raw_perfs.items():
            mds_key = "mds.{}".format(rank)
            mds_metrics = metrics.setdefault(mds_key, {})
            mds_metrics.update(counters[1])
        return result

    def extract_query_filters(self, cmd):
        mds_rank_spec = cmd.get('mds_rank', None)
        client_id_spec = cmd.get('client_id', None)
        client_ip_spec = cmd.get('client_ip', None)

        self.log.debug("mds_rank_spec={0}, client_id_spec={1}, client_ip_spec={2}".format(
            mds_rank_spec, client_id_spec, client_ip_spec))

        mds_ranks = extract_mds_ranks_from_spec(mds_rank_spec)
        client_id = extract_client_id_from_spec(client_id_spec)
        client_ip = extract_client_ip_from_spec(client_ip_spec)

        return FilterSpec(mds_ranks, client_id, client_ip)

    def get_perf_data(self, cmd):
        filter_spec = self.extract_query_filters(cmd)

        counters = {}
        with self.lock:
            user_query = self.register_query(filter_spec)
            result = self.generate_report(user_query)
        return 0, json.dumps(result), ""