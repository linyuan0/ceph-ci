// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "include/buffer.h"
#include "include/stringify.h"
#include "common/ceph_argparse.h"
#include "common/config_proxy.h"
#include "common/errno.h"
#include "erasure-code/ErasureCode.h"
#include "erasure-code/ErasureCodePlugin.h"
#include "global/global_context.h"
#include "global/global_init.h"
#include "osd/ECUtil.h"

#include <iostream>
#include <map>
#include <string>
#include <vector>

#include <boost/algorithm/string.hpp>

void usage(const std::string message, ostream &out) {
  if (!message.empty()) {
    out << message << std::endl;
    out << "" << std::endl;
  }
  out << "usage: ceph-erasure-code-tool encode <profile> <stripe_unit> <want_to_encode> <fname>" << std::endl;
  out << "       ceph-erasure-code-tool decode <profile> <stripe_unit> <want_to_decode> <fname>" << std::endl;
  out << "" << std::endl;
  out << "  profile         - comma separated list of erasure-code profile settings" << std::endl;
  out << "                    example: plugin=jerasure,technique=reed_sol_van,k=3,m=2" << std::endl;
  out << "  stripe_unit     - stripe unit" << std::endl;
  out << "  want_to_encode  - comma separated list of shards to encode" << std::endl;
  out << "  want_to_decode  - comma separated list of shards to decode" << std::endl;
  out << "  fname           - name for input/output files" << std::endl;
  out << "                    when encoding input is read form {fname} file," << std::endl;
  out << "                                  result is stored in {fname}.{shard} files" << std::endl;
  out << "                    when decoding input is read form {fname}.{shard} files," << std::endl;
  out << "                                  result is stored in {fname} file" << std::endl;
}

int main(int argc, const char **argv) {
  std::vector<const char*> args;
  argv_to_vec(argc, argv, args);
  auto cct = global_init(nullptr, args, CEPH_ENTITY_TYPE_CLIENT,
                         CODE_ENVIRONMENT_UTILITY,
                         CINIT_FLAG_NO_MON_CONFIG);

  if (args.empty() || args[0] == std::string("-h") ||
      args[0] == std::string("--help")) {
    usage("", std::cout);
    return 0;
  }
  if (args.size() < 5) {
    usage("not enought arguments", std::cerr);
    return 1;
  }

  std::string command = args[0];

  ceph::ErasureCodeProfile profile;
  std::vector<std::string> profile_str;
  boost::split(profile_str, args[1], boost::is_any_of(", "));
  for (auto &opt_str : profile_str) {
    std::vector<std::string> opt;
    boost::split(opt, opt_str, boost::is_any_of("="));
    if (opt.size() <= 1) {
      usage("invalid profile", std::cerr);
      return 1;
    }
    profile[opt[0]] = opt[1];
  }
  auto plugin = profile.find("plugin");
  if (plugin == profile.end()) {
      usage("invalid profile: plugin not specified", std::cerr);
      return 1;
  }

  ceph::ErasureCodeInterfaceRef ec_impl;
  stringstream ss;
  ceph::ErasureCodePluginRegistry::instance().factory(
    plugin->second, g_conf().get_val<std::string>("erasure_code_dir"),
    profile, &ec_impl, &ss);
  if (!ec_impl) {
    usage("invalid profile: " + ss.str(), std::cerr);
    return 1;
  }

  uint64_t stripe_unit = atoi(args[2]);
  if (stripe_unit <= 0) {
    usage("invalid stripe unit", std::cerr);
    return 1;
  }

  uint64_t stripe_size = atoi(profile["k"].c_str());
  ceph_assert(stripe_size > 0);
  uint64_t stripe_width = stripe_size * stripe_unit;
  ECUtil::stripe_info_t sinfo(stripe_size, stripe_width);

  std::map<int, ceph::bufferlist> encoded_data;
  std::vector<std::string> shards;
  boost::split(shards, args[3], boost::is_any_of(","));
  for (auto &shard : shards) {
    encoded_data[atoi(shard.c_str())] = {};
  }
  ceph::bufferlist decoded_data;
  std::string fname = args[4];

  if (command == "encode") {
    std::string error;
    int r = decoded_data.read_file(fname.c_str(), &error);
    if (r < 0) {
      std::cerr << "failed to read " << fname << ": " << error << std::endl;
      return 1;
    }

    if (decoded_data.length() % stripe_width != 0) {
      uint64_t pad = stripe_width - decoded_data.length() % stripe_width;
      decoded_data.append_zero(pad);
    }

    std::set<int> want;
    for (auto& it: encoded_data) {
      want.insert(it.first);
    }
    encoded_data.clear();

    r = ECUtil::encode(sinfo, ec_impl, decoded_data, want, &encoded_data);
    if (r < 0) {
      std::cerr << "failed to encode: " << cpp_strerror(r) << std::endl;
      return 1;
    }

    for (auto it : encoded_data) {
      std::string name = fname + "." + stringify(it.first);
      r = it.second.write_file(name.c_str());
      if (r < 0) {
        std::cerr << "failed to write " << name << ": " << cpp_strerror(r)
                  << std::endl;
        return 1;
      }
    }
  } else if (command == "decode") {
    for (auto &it : encoded_data) {
      std::string name = fname + "." + stringify(it.first);
      std::string error;
      int r = it.second.read_file(name.c_str(), &error);
      if (r < 0) {
        std::cerr << "failed to read " << name << ": " << error << std::endl;
        return 1;
      }
    }

    int r = ECUtil::decode(sinfo, ec_impl, encoded_data, &decoded_data);
    if (r < 0) {
      std::cerr << "failed to decode: " << cpp_strerror(r) << std::endl;
      return 1;
    }

    r = decoded_data.write_file(fname.c_str());
    if (r < 0) {
      std::cerr << "failed to write " << fname << ": " << cpp_strerror(r)
                << std::endl;
      return 1;
    }
  } else {
    usage("invalid command: " + command, std::cerr);
    return 1;
  }

  return 0;
}
