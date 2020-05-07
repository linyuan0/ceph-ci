// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab ft=cpp

/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2018 Red Hat, Inc.
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation. See file COPYING.
 *
 */

#pragma once

#include <cstdint>
#include <memory>
#include <type_traits>

#include <boost/intrusive/list.hpp>
#include <boost/system/error_code.hpp>
#include "include/rados/librados_fwd.hpp"
#include "common/async/yield_context.h"

#include "services/svc_rados.h" // cant forward declare RGWSI_RADOS::Obj

#include "rgw_common.h"
#include "rgw_rados.h"

#include "include/function2.hpp"
#include "include/neorados/RADOS.hpp"

namespace rgw {

struct AioResult {
  RGWSI_RADOS::Obj obj;
  uint64_t id = 0; // id allows caller to associate a result with its request
  bufferlist data; // result buffer for reads
  int result = 0;
  std::aligned_storage_t<3 * sizeof(void*)> user_data;

  AioResult() = default;
  AioResult(const AioResult&) = delete;
  AioResult& operator =(const AioResult&) = delete;
  AioResult(AioResult&&) = delete;
  AioResult& operator =(AioResult&&) = delete;
};
struct AioResultEntry : AioResult, boost::intrusive::list_base_hook<> {
  virtual ~AioResultEntry() {}
};
// a list of polymorphic entries that frees them on destruction
template <typename T, typename ...Args>
struct OwningList : boost::intrusive::list<T, Args...> {
  OwningList() = default;
  ~OwningList() { this->clear_and_dispose(std::default_delete<T>{}); }
  OwningList(OwningList&&) = default;
  OwningList& operator=(OwningList&&) = default;
  OwningList(const OwningList&) = delete;
  OwningList& operator=(const OwningList&) = delete;
};
using AioResultList = OwningList<AioResultEntry>;

// returns the first error code or 0 if all succeeded
inline int check_for_errors(const AioResultList& results) {
  for (auto& e : results) {
    if (e.result < 0) {
      return e.result;
    }
  }
  return 0;
}

// interface to submit async librados operations and wait on their completions.
// each call returns a list of results from prior completions
class Aio {
 public:
  using OpFunc = fu2::unique_function<void(Aio*, AioResult&) &&>;

  virtual ~Aio() {}

  virtual AioResultList get(const RGWSI_RADOS::Obj& obj,
			    OpFunc&& f,
			    uint64_t cost, uint64_t id) = 0;
  virtual void put(AioResult& r) = 0;

  // poll for any ready completions without waiting
  virtual AioResultList poll() = 0;

  // return any ready completions. if there are none, wait for the next
  virtual AioResultList wait() = 0;

  // wait for all outstanding completions and return their results
  virtual AioResultList drain() = 0;

  static OpFunc librados_op(librados::ObjectReadOperation&& op,
                            optional_yield y);
  static OpFunc librados_op(librados::ObjectWriteOperation&& op,
                            optional_yield y);
};

} // namespace rgw

// Just so we can have both versions sit side-by-side.

namespace bs = boost::system;
namespace R = neorados;

namespace neo {

struct AioResult {
  neo_obj_ref obj;
  uint64_t id = 0; // id allows caller to associate a result with its request
  bs::error_code result;
  ceph::buffer::list data;
  std::aligned_storage_t<3 * sizeof(void*)> user_data;

  AioResult(neo_obj_ref obj)
    : obj(std::move(obj)) {}
  AioResult(const AioResult&) = delete;
  AioResult& operator =(const AioResult&) = delete;
  AioResult(AioResult&&) = delete;
  AioResult& operator =(AioResult&&) = delete;
};
struct AioResultEntry : AioResult, boost::intrusive::list_base_hook<> {
  AioResultEntry(neo_obj_ref obj) : AioResult(std::move(obj)) {}
  virtual ~AioResultEntry() {}
};
// a list of polymorphic entries that frees them on destruction
template <typename T, typename ...Args>
struct OwningList : boost::intrusive::list<T, Args...> {
  OwningList() = default;
  ~OwningList() { this->clear_and_dispose(std::default_delete<T>{}); }
  OwningList(OwningList&&) = default;
  OwningList& operator=(OwningList&&) = default;
  OwningList(const OwningList&) = delete;
  OwningList& operator=(const OwningList&) = delete;
};
using AioResultList = OwningList<AioResultEntry>;

// returns the first error code or 0 if all succeeded
inline bs::error_code check_for_errors(const AioResultList& results) {
  for (auto& e : results) {
    if (e.result) {
      return e.result;
    }
  }
  return {};
}

// interface to submit async RADOS operations and wait on their completions.
// each call returns a list of results from prior completions
class Aio {
public:
  using OpFunc = fu2::unique_function<void(Aio*, AioResult&) &&>;

  Aio() = default;
  virtual ~Aio() {}

  virtual AioResultList get(neo_obj_ref obj,
			    OpFunc&& f,
			    uint64_t cost, uint64_t id) = 0;
  virtual void put(AioResult& r) = 0;

  // poll for any ready completions without waiting
  virtual AioResultList poll() = 0;

  // return any ready completions. if there are none, wait for the next
  virtual AioResultList wait() = 0;

  // wait for all outstanding completions and return their results
  virtual AioResultList drain() = 0;

  static OpFunc rados_op(R::ReadOp&& op, optional_yield y);
  static OpFunc rados_op(R::WriteOp&& op, optional_yield y);
};
}
