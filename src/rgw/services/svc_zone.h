#ifndef CEPH_RGW_SERVICES_ZONE_H
#define CEPH_RGW_SERVICES_ZONE_H


#include "rgw/rgw_service.h"


class RGWSI_RADOS;

struct RGWZoneGroup;
struct RGWZone;
struct RGWZoneParams;
struct RGWPeriod;
struct RGWRealm;
struct RGWZonePlacementInfo;

class RGWRESTConn;

class RGWS_Zone : public RGWService
{
public:
  RGWS_Zone(CephContext *cct) : RGWService(cct, "zone") {}

  int create_instance(const std::string& conf, RGWServiceInstanceRef *instance);
};

class RGWSI_Zone : public RGWServiceInstance
{
  std::shared_ptr<RGWSI_RADOS> rados_svc;

  std::shared_ptr<RGWRealm> realm;
  std::shared_ptr<RGWZoneGroup> zonegroup;
  std::shared_ptr<RGWZone> zone_public_config; /* external zone params, e.g., entrypoints, log flags, etc. */  
  std::shared_ptr<RGWZoneParams> zone_params; /* internal zone params, e.g., rados pools */
  std::shared_ptr<RGWPeriod> current_period;
  uint32_t zone_short_id{0};
  bool writeable_zone{false};

  std::map<std::string, RGWServiceInstance::dependency> get_deps();
  int init(const std::string& conf, std::map<std::string, RGWServiceInstanceRef>& dep_refs);

  RGWRESTConn *rest_master_conn{nullptr};
  map<string, RGWRESTConn *> zone_conn_map;
  map<string, RGWRESTConn *> zone_data_sync_from_map;
  map<string, RGWRESTConn *> zone_data_notify_to_map;
  map<string, RGWRESTConn *> zonegroup_conn_map;

  map<string, string> zone_id_by_name;
  map<string, RGWZone> zone_by_id;

public:
  RGWSI_Zone(RGWService *svc, CephContext *cct): RGWServiceInstance(svc, cct) {}

  RGWZoneParams& get_zone_params();
  RGWPeriod& get_current_period();
  RGWRealm& get_realm();
  RGWZoneGroup& get_zonegroup();
  int get_zonegroup(const string& id, RGWZoneGroup& zonegroup);
  RGWZone& get_zone();

  const string& zone_name();
  const string& zone_id();
  uint32_t get_zone_short_id() const;

  const string& get_current_period_id();
  bool has_zonegroup_api(const std::string& api) const;

  bool zone_is_writeable();
  bool zone_syncs_from(RGWZone& target_zone, RGWZone& source_zone);
  bool get_redirect_zone_endpoint(string *endpoint);

  RGWRESTConn *get_master_conn() {
    return rest_master_conn;
  }

  map<string, RGWRESTConn *>& get_zone_conn_map() {
    return zone_conn_map;
  }

  bool find_zone_by_id(const string& id, RGWZone **zone);

  RGWRESTConn *get_zone_conn_by_id(const string& id);
  RGWRESTConn *get_zone_conn_by_name(const string& name);
  bool find_zone_id_by_name(const string& name, string *id);

  int select_bucket_placement(RGWUserInfo& user_info, const string& zonegroup_id, const string& rule,
                              string *pselected_rule_name, RGWZonePlacementInfo *rule_info);
  int select_legacy_bucket_placement(RGWZonePlacementInfo *rule_info);
  int select_new_bucket_location(RGWUserInfo& user_info, const string& zonegroup_id, const string& rule,
                                 string *pselected_rule_name, RGWZonePlacementInfo *rule_info);
  int select_bucket_location_by_rule(const string& location_rule, RGWZonePlacementInfo *rule_info);

  bool is_meta_master() const;

  bool need_to_log_data() const;
  bool need_to_log_metadata() const;
  bool can_reshard() const;
};

#endif
