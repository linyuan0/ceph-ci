#!/usr/bin/env bash
#
# Copyright (C) 2018 Red Hat <contact@redhat.com>
#
# Author: David Zafman <dzafman@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU Library Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Library Public License for more details.
#

source $CEPH_ROOT/qa/standalone/ceph-helpers.sh

function run() {
    local dir=$1
    shift

    export CEPH_MON="127.0.0.1:7180" # git grep '\<7180\>' : there must be only one
    export CEPH_ARGS
    CEPH_ARGS+="--fsid=$(uuidgen) --auth-supported=none "
    CEPH_ARGS+="--mon-host=$CEPH_MON "
    CEPH_ARGS+="--osd_min_pg_log_entries=5 --osd_max_pg_log_entries=10 "
    CEPH_ARGS+="--fake_statfs_for_testing=3686400 "
    CEPH_ARGS+="--osd_max_backfills=10 "
    export objects=600
    export poolprefix=test

    local funcs=${@:-$(set | sed -n -e 's/^\(TEST_[0-9a-z_]*\) .*/\1/p')}
    for func in $funcs ; do
        setup $dir || return 1
        $func $dir || return 1
        teardown $dir || return 1
    done
}


function get_num_in_state() {
    local state=$1
    local expression
    expression+="select(contains(\"${state}\"))"
    ceph --format json pg dump pgs 2>/dev/null | \
        jq ".pg_stats | [.[] | .state | $expression] | length"
}


function wait_for_state() {
    local state=$1
    local num_in_state=-1
    local cur_in_state
    local -a delays=($(get_timeout_delays $2 5))
    local -i loop=0

    flush_pg_stats || return 1
    while test $(get_num_pgs) == 0 ; do
	sleep 1
    done

    while true ; do
        cur_in_state=$(get_num_in_state ${state})
        test $cur_in_state = "0" && break
        if test $cur_in_state != $num_in_state ; then
            loop=0
            num_in_state=$cur_in_state
        elif (( $loop >= ${#delays[*]} )) ; then
            ceph pg dump pgs
            return 1
        fi
        sleep ${delays[$loop]}
        loop+=1
    done
    return 0
}


function wait_for_backfill() {
    local timeout=$1
    wait_for_state backfilling $timeout
}


function wait_for_active() {
    local timeout=$1
    wait_for_state activating $timeout
}

# All tests are created in an environment which has fake total space
# of 1228800 which can hold 200 6K replicated objects.

# Create 2 pools which size 2 on 3 OSDs which should
# result in 1 OSD with overlapping replicas, so both
# pools can't fix.  We assume pgid 1.0 and 2.0 won't
# map to the same 2 OSDs.
function TEST_backfill_test_simple() {
    local dir=$1
    local pools=2
    local OSDS=3

    run_mon $dir a || return 1
    run_mgr $dir x || return 1
    export CEPH_ARGS

    for osd in $(seq 0 $(expr $OSDS - 1))
    do
      run_osd $dir $osd || return 1
    done

    for p in $(seq 1 $pools)
    do
      create_pool "${poolprefix}$p" 1 1
      ceph osd pool set "${poolprefix}$p" size 1
    done

    wait_for_clean || return 1

    # This won't work is if the 2 pools primary and only osds
    # are the same.

    dd if=/dev/urandom of=$dir/datafile bs=1024 count=4
    for o in $(seq 1 $objects)
    do
      for p in $(seq 1 $pools)
      do
	rados -p "${poolprefix}$p" put obj$o $dir/datafile
      done
    done

    ceph pg dump pgs

    for p in $(seq 1 $pools)
    do
      ceph osd pool set "${poolprefix}$p" size 2
    done
    sleep 5

    wait_for_backfill 60
    wait_for_active 60

    ERRORS=0
    if [ "$(ceph pg dump pgs | grep +backfill_toofull | wc -l)" != "1" ];
    then
      echo "One pool should have been in backfill_toofull"
      ERRORS="$(expr $ERRORS + 1)"
    fi

    expected="$(expr $pools - 1)"
    if [ "$(ceph pg dump pgs | grep active+clean | wc -l)" != "$expected" ];
    then
      echo "$expected didn't finish backfill"
      ERRORS="$(expr $ERRORS + 1)"
    fi

    ceph pg dump pgs

    if [ $ERRORS != "0" ];
    then
      return 1
    fi

    for i in $(seq 1 $pools)
    do
      delete_pool "${poolprefix}$i"
    done
    kill_daemons $dir || return 1
    ! grep -q "num_bytes mismatch" $dir/osd.*.log || return 1
}


# Create 4 pools on 10 OSDs
function TEST_backfill_test_multi() {
    local dir=$1
    local pools=8
    local OSDS=20

    run_mon $dir a || return 1
    run_mgr $dir x || return 1
    export CEPH_ARGS

    for osd in $(seq 0 $(expr $OSDS - 1))
    do
      run_osd $dir $osd || return 1
    done

    for p in $(seq 1 $pools)
    do
      create_pool "${poolprefix}$p" 1 1
      ceph osd pool set "${poolprefix}$p" size 1
    done

    wait_for_clean || return 1

    dd if=/dev/urandom of=$dir/datafile bs=1024 count=4
    for o in $(seq 1 $objects)
    do
      for p in $(seq 1 $pools)
      do
	rados -p "${poolprefix}$p" put obj$o $dir/datafile
      done
    done

    ceph pg dump pgs

    for p in $(seq 1 $pools)
    do
      ceph osd pool set "${poolprefix}$p" size 2
    done
    sleep 5

    wait_for_backfill 60
    wait_for_active 60

    ERRORS=0
    full="$(ceph pg dump pgs | grep +backfill_toofull | wc -l)"
    if [ "$full" -lt "1" ];
    then
      echo "At least one pool should have been in backfill_toofull"
      ERRORS="$(expr $ERRORS + 1)"
    fi

    expected="$(expr $pools - $full)"
    if [ "$(ceph pg dump pgs | grep active+clean | wc -l)" != "$expected" ];
    then
      echo "$expected didn't finish backfill"
      ERRORS="$(expr $ERRORS + 1)"
    fi

    ceph pg dump pgs

    if [ $ERRORS != "0" ];
    then
      return 1
    fi

    for i in $(seq 1 $pools)
    do
      delete_pool "${poolprefix}$i"
    done
    kill_daemons $dir || return 1
    ! grep -q "num_bytes mismatch" $dir/osd.*.log || return 1
}


function TEST_backfill_test_sametarget() {
    local dir=$1
    local pools=10
    local OSDS=5

    run_mon $dir a || return 1
    run_mgr $dir x || return 1
    export CEPH_ARGS

    for osd in $(seq 0 $(expr $OSDS - 1))
    do
      run_osd $dir $osd || return 1
    done

    for p in $(seq 1 $pools)
    do
      create_pool "${poolprefix}$p" 1 1
      ceph osd pool set "${poolprefix}$p" size 2
    done
    sleep 5

    wait_for_clean || return 1

    ceph pg dump pgs

    # Find 2 pools with a pg that distinct primaries but second
    # replica on the same osd.
    local PG1
    local POOLNUM1
    local pool1
    local chk_osd1
    local chk_osd2

    local PG2
    local POOLNUM2
    local pool2
    for p in $(seq 1 $pools)
    do
      ceph pg map ${p}.0 --format=json | jq '.acting[]' > $dir/acting
      local test_osd1=$(head -1 $dir/acting)
      local test_osd2=$(tail -1 $dir/acting)
      if [ $p = "1" ];
      then
        PG1="${p}.0"
        POOLNUM1=$p
        pool1="${poolprefix}$p"
        chk_osd1=$test_osd1
        chk_osd2=$test_osd2
      elif [ $chk_osd1 != $test_osd1 -a $chk_osd2 = $test_osd2 ];
      then
        PG2="${p}.0"
        POOLNUM2=$p
        pool2="${poolprefix}$p"
        break
      fi
    done
    rm -f $dir/acting

    if [ "$pool2" = "" ];
    then
      echo "Failure to find appropirate PGs"
      return 1
    fi

    for p in $(seq 1 $pools)
    do
      if [ $p != $POOLNUM1 -a $p != $POOLNUM2 ];
      then
        delete_pool ${poolprefix}$p
      fi
    done

    ceph osd pool set $pool1 size 1
    ceph osd pool set $pool2 size 1

    wait_for_clean || return 1

    dd if=/dev/urandom of=$dir/datafile bs=1024 count=4
    for i in $(seq 1 $objects)
    do
	rados -p $pool1 put obj$i $dir/datafile
        rados -p $pool2 put obj$i $dir/datafile
    done

    ceph osd pool set $pool1 size 2
    ceph osd pool set $pool2 size 2
    sleep 5

    wait_for_backfill 60
    wait_for_active 60

    ERRORS=0
    if [ "$(ceph pg dump pgs | grep +backfill_toofull | wc -l)" != "1" ];
    then
      echo "One pool should have been in backfill_toofull"
      ERRORS="$(expr $ERRORS + 1)"
    fi

    if [ "$(ceph pg dump pgs | grep active+clean | wc -l)" != "1" ];
    then
      echo "One didn't finish backfill"
      ERRORS="$(expr $ERRORS + 1)"
    fi

    ceph pg dump pgs

    if [ $ERRORS != "0" ];
    then
      return 1
    fi

    delete_pool $pool1
    delete_pool $pool2
    kill_daemons $dir || return 1
    ! grep -q "num_bytes mismatch" $dir/osd.*.log || return 1
}

function TEST_backfill_multi_partial() {
    local dir=$1
    local EC=$2
    local pools=2
    local OSDS=3

    run_mon $dir a || return 1
    run_mgr $dir x || return 1
    export CEPH_ARGS

    for osd in $(seq 0 $(expr $OSDS - 1))
    do
      run_osd $dir $osd || return 1
    done

    create_pool fillpool 1 1
    ceph osd pool set fillpool size 1
    for p in $(seq 1 $pools)
    do
      create_pool "${poolprefix}$p" 1 1
      ceph osd pool set "${poolprefix}$p" size 2
    done

    wait_for_clean || return 1

    # Partially fill an osd
    # We have room for 200 6K replicated objects, if we create 3780 byte objects
    # there is 1228800 - (2611 *200) = 522200 which uses the fill pool and one
    # replica from the other 2 is 85% of 1228800
    dd if=/dev/urandom of=$dir/datafile bs=2611 count=1
    for o in $(seq 1 $objects)
    do
      rados -p fillpool put obj-fill-${o} $dir/datafile
    done

    local fillosd=$(get_primary fillpool obj-fill-1)
    osd=$(expr $fillosd + 1)
    if [ "$osd" = "$OSDS" ]; then
      osd="0"
    fi

    sleep 5
    kill $(cat $dir/osd.$fillosd.pid)
    ceph osd out osd.$fillosd
    sleep 2

    _objectstore_tool_nodown $dir $fillosd --op export-remove --pgid 1.0 --file $dir/fillexport.out || return 1
    activate_osd $dir $fillosd || return 1

    ceph pg dump pgs

    dd if=/dev/urandom of=$dir/datafile bs=1024 count=1
    for o in $(seq 1 $objects)
    do
      rados -p "${poolprefix}1" put obj-1-${o} $dir/datafile
    done

    ceph pg dump pgs
    _objectstore_tool_nowait $dir $osd --op export --pgid 2.0 --file $dir/export.out
    kill $(cat $dir/osd.$fillosd.pid)
    sleep 5
    _objectstore_tool_nodown $dir $fillosd --force --op remove --pgid 2.0
    _objectstore_tool_nodown $dir $fillosd --debug --op import --pgid 2.0 --file $dir/export.out || return 1
    _objectstore_tool_nodown $dir $fillosd --op import --pgid 1.0 --file $dir/fillexport.out || return 1
    ceph pg dump pgs
    sleep 20
    ceph pg dump pgs

    # re-write everything
    dd if=/dev/urandom of=$dir/datafile bs=2611 count=1
    for o in $(seq 1 $objects)
    do
      for p in $(seq 1 $pools)
      do
	rados -p "${poolprefix}$p" put obj-${p}-${o} $dir/datafile
      done
    done

    kill $(cat $dir/osd.$osd.pid)
    ceph osd out osd.$osd

    activate_osd $dir $fillosd || return 1
    ceph osd in osd.$fillosd
    sleep 15

    wait_for_backfill 60
    wait_for_active 60

    flush_pg_stats || return 1
    ceph pg dump pgs

    ERRORS=0
    if [ "$(ceph pg dump pgs | grep -v "^1.0" | grep +backfill_toofull | wc -l)" != "1" ];
    then
      echo "One pool should have been in backfill_toofull"
      ERRORS="$(expr $ERRORS + 1)"
    fi

    if [ "$(ceph pg dump pgs | grep -v "^1.0" | grep active+clean | wc -l)" != "1" ];
    then
      echo "One didn't finish backfill"
      ERRORS="$(expr $ERRORS + 1)"
    fi

    if [ $ERRORS != "0" ];
    then
      return 1
    fi

    delete_pool fillpool
    for i in $(seq 1 $pools)
    do
      delete_pool "${poolprefix}$i"
    done
    kill_daemons $dir || return 1
    ! grep -q "num_bytes mismatch" $dir/osd.*.log || return 1
}

# Make sure that the amount of bytes already on the replica doesn't
# cause an out of space condition
function TEST_backfill_grow() {
    local dir=$1
    local poolname="test"
    local OSDS=3

    run_mon $dir a || return 1
    run_mgr $dir x || return 1

    for osd in $(seq 0 $(expr $OSDS - 1))
    do
      run_osd $dir $osd || return 1
    done

    create_pool $poolname 1 1
    ceph osd pool set $poolname size 3
    sleep 5

    wait_for_clean || return 1

    dd if=/dev/urandom of=${dir}/4kdata bs=1k count=4
    for i in $(seq 1 $objects)
    do
	rados -p $poolname put obj$i $dir/4kdata
    done

    local PG=$(get_pg $poolname obj1)
    # Remember primary during the backfill
    local primary=$(get_primary $poolname obj1)
    local otherosd=$(get_not_primary $poolname obj1)

    ceph osd set noout
    kill_daemons $dir TERM $otherosd || return 1

    rmobjects=$(expr $objects / 4)
    for i in $(seq 1 $rmobjects)
    do
        rados -p $poolname rm obj$i
    done

    dd if=/dev/urandom of=${dir}/6kdata bs=6k count=1
    for i in $(seq $(expr $rmobjects + 1) $objects)
    do
	rados -p $poolname put obj$i $dir/6kdata
    done

    activate_osd $dir $otherosd || return 1

    ceph tell osd.$primary debug kick_recovery_wq 0

    sleep 2

    wait_for_clean || return 1

    delete_pool $poolname
    kill_daemons $dir || return 1
    ! grep -q "num_bytes mismatch" $dir/osd.*.log || return 1
}

function TEST_ec_backfill_simple() {
    local dir=$1
    local EC=$2
    local pools=1
    local OSDS=6
    local k=3
    local m=2
    local ecobjects=$(expr $objects / $k)

    run_mon $dir a || return 1
    run_mgr $dir x || return 1
    export CEPH_ARGS

    for osd in $(seq 0 $(expr $OSDS - 1))
    do
      run_osd $dir $osd || return 1
    done

    create_pool fillpool 1 1
    ceph osd pool set fillpool size 1

    # Partially fill an osd
    # We have room for 200 18K replicated objects, if we create 13K objects
    # there is only 3600K - (13 * 200) = 1000K which won't hold
    # a k=3 shard below (24K / 3) * 200 = 1600K
    dd if=/dev/urandom of=$dir/datafile bs=1024 count=13
    for o in $(seq 1 $ecobjects)
    do
      rados -p fillpool put obj$o $dir/datafile
    done

    local fillosd=$(get_primary fillpool obj1)
    osd=$(expr $fillosd + 1)
    if [ "$osd" = "$OSDS" ]; then
      osd="0"
    fi

    sleep 5
    kill $(cat $dir/osd.$fillosd.pid)
    ceph osd out osd.$fillosd
    sleep 2
    ceph osd erasure-code-profile set ec-profile k=$k m=$m crush-failure-domain=osd technique=reed_sol_van plugin=jerasure || return 1

    for p in $(seq 1 $pools)
    do
        ceph osd pool create "${poolprefix}$p" 1 1 erasure ec-profile
    done

    # Can't wait for clean here because we created a stale pg
    #wait_for_clean || return 1
    sleep 5

    ceph pg dump pgs

    dd if=/dev/urandom of=$dir/datafile bs=1024 count=24
    for o in $(seq 1 $ecobjects)
    do
      for p in $(seq 1 $pools)
      do
	rados -p "${poolprefix}$p" put obj$o $dir/datafile
      done
    done

    kill $(cat $dir/osd.$osd.pid)
    ceph osd out osd.$osd

    activate_osd $dir $fillosd || return 1
    ceph osd in osd.$fillosd
    sleep 30

    ceph pg dump pgs

    wait_for_backfill 60
    wait_for_active 60

    ceph pg dump pgs

    ERRORS=0
    if [ "$(ceph pg dump pgs | grep -v "^1.0" | grep +backfill_toofull | wc -l)" != "1" ]; then
      echo "One pool should have been in backfill_toofull"
      ERRORS="$(expr $ERRORS + 1)"
    fi

    if [ $ERRORS != "0" ];
    then
      return 1
    fi

    delete_pool fillpool
    for i in $(seq 1 $pools)
    do
      delete_pool "${poolprefix}$i"
    done
    kill_daemons $dir || return 1
}

function TEST_ec_backfill_multi() {
    local dir=$1
    local EC=$2
    local pools=2
    local OSDS=6
    local k=3
    local m=2
    local ecobjects=$(expr $objects / $k)

    run_mon $dir a || return 1
    run_mgr $dir x || return 1
    export CEPH_ARGS

    for osd in $(seq 0 $(expr $OSDS - 1))
    do
      run_osd $dir $osd || return 1
    done

    create_pool fillpool 1 1
    ceph osd pool set fillpool size 1

    # Partially fill an osd
    # We have room for 200 18K replicated objects, if we create 5K objects
    # there is only 3600K - (6 * 200) = 2400K which will only hold
    # one k=3 shard below (21K / 3) * 200 = 1400K
    dd if=/dev/urandom of=$dir/datafile bs=1024 count=6
    for o in $(seq 1 $ecobjects)
    do
      rados -p fillpool put obj$o $dir/datafile
    done

    local fillosd=$(get_primary fillpool obj1)
    osd=$(expr $fillosd + 1)
    if [ "$osd" = "$OSDS" ]; then
      osd="0"
    fi

    sleep 5
    kill $(cat $dir/osd.$fillosd.pid)
    ceph osd out osd.$fillosd
    sleep 2
    ceph osd erasure-code-profile set ec-profile k=3 m=2 crush-failure-domain=osd technique=reed_sol_van plugin=jerasure || return 1

    for p in $(seq 1 $pools)
    do
        ceph osd pool create "${poolprefix}$p" 1 1 erasure ec-profile
    done

    # Can't wait for clean here because we created a stale pg
    #wait_for_clean || return 1
    sleep 5

    ceph pg dump pgs

    dd if=/dev/urandom of=$dir/datafile bs=1024 count=21
    for o in $(seq 1 $ecobjects)
    do
      for p in $(seq 1 $pools)
      do
	rados -p "${poolprefix}$p" put obj$o-$p $dir/datafile
      done
    done

    kill $(cat $dir/osd.$osd.pid)
    ceph osd out osd.$osd

    activate_osd $dir $fillosd || return 1
    ceph osd in osd.$fillosd
    sleep 15

    wait_for_backfill 60
    wait_for_active 60

    ceph pg dump pgs

    ERRORS=0
    if [ "$(ceph pg dump pgs | grep -v "^1.0" | grep +backfill_toofull | wc -l)" != "1" ];
    then
      echo "One pool should have been in backfill_toofull"
      ERRORS="$(expr $ERRORS + 1)"
    fi

    if [ "$(ceph pg dump pgs | grep -v "^1.0" | grep active+clean | wc -l)" != "1" ];
    then
      echo "One didn't finish backfill"
      ERRORS="$(expr $ERRORS + 1)"
    fi

    if [ $ERRORS != "0" ];
    then
      return 1
    fi

    delete_pool fillpool
    for i in $(seq 1 $pools)
    do
      delete_pool "${poolprefix}$i"
    done
    kill_daemons $dir || return 1
}

function TEST_ec_backfill_multi_partial() {
    local dir=$1
    local EC=$2
    local pools=2
    local OSDS=6

    run_mon $dir a || return 1
    run_mgr $dir x || return 1
    export CEPH_ARGS

    for osd in $(seq 0 $(expr $OSDS - 1))
    do
      run_osd $dir $osd || return 1
    done

    create_pool fillpool 1 1
    ceph osd pool set fillpool size 1

    # Partially fill an osd
    # We have room for 200 6K replicated objects, if we create 4k byte objects
    # there is 1228800 - (4096 *200) = 8819200 which won't hold 2 k=3 shard
    # of 200 4K objects which takes 4K * 200 / 3 = 273066 with enough to spare
    # to not get out of space.
    dd if=/dev/urandom of=$dir/datafile bs=1024 count=4
    for o in $(seq 1 $objects)
    do
      rados -p fillpool put obj$o $dir/datafile
    done

    local fillosd=$(get_primary fillpool obj1)
    osd=$(expr $fillosd + 1)
    if [ "$osd" = "$OSDS" ]; then
      osd="0"
    fi

    sleep 5
    kill $(cat $dir/osd.$fillosd.pid)
    ceph osd out osd.$fillosd
    sleep 2
    ceph osd erasure-code-profile set ec-profile k=3 m=2 crush-failure-domain=osd technique=reed_sol_van plugin=jerasure || return 1

    for p in $(seq 1 $pools)
    do
        ceph osd pool create "${poolprefix}$p" 1 1 erasure ec-profile
    done

    # Can't wait for clean here because we created a stale pg
    #wait_for_clean || return 1
    sleep 5

    ceph pg dump pgs

    dd if=/dev/urandom of=$dir/datafile bs=1024 count=4
    for o in $(seq 1 $objects)
    do
      for p in $(seq 1 $pools)
      do
	rados -p "${poolprefix}$p" put obj$o $dir/datafile
      done
    done

    #ceph pg map 2.0 --format=json | jq '.'
    objectstore_tool $dir $osd --op export --pgid 2.0 --file $dir/export.out
    objectstore_tool $dir $fillosd --op import --pgid 2.0 --file $dir/export.out

    kill $(cat $dir/osd.$osd.pid)
    ceph osd out osd.$osd

    activate_osd $dir $fillosd || return 1
    ceph osd in osd.$fillosd
    sleep 15

    wait_for_backfill 60
    wait_for_active 60

    ERRORS=0
    if [ "$(ceph pg dump pgs | grep -v "^1.0" | grep +backfill_toofull | wc -l)" != "1" ];
    then
      echo "One pool should have been in backfill_toofull"
      ERRORS="$(expr $ERRORS + 1)"
    fi

    if [ "$(ceph pg dump pgs | grep -v "^1.0" | grep active+clean | wc -l)" != "1" ];
    then
      echo "One didn't finish backfill"
      ERRORS="$(expr $ERRORS + 1)"
    fi

    ceph pg dump pgs

    if [ $ERRORS != "0" ];
    then
      return 1
    fi

    delete_pool fillpool
    for i in $(seq 1 $pools)
    do
      delete_pool "${poolprefix}$i"
    done
    kill_daemons $dir || return 1
}

function TEST_ec_backfill_grow() {
    local dir=$1
    local poolname="test"
    local OSDS=6
    local k=3
    local m=2

    run_mon $dir a || return 1
    run_mgr $dir x || return 1

    for osd in $(seq 0 $(expr $OSDS - 1))
    do
      run_osd $dir $osd || return 1
    done

    ceph osd erasure-code-profile set ec-profile k=$k m=$m crush-failure-domain=osd technique=reed_sol_van plugin=jerasure || return 1
    ceph osd pool create $poolname 1 1 erasure ec-profile

    wait_for_clean || return 1

    dd if=/dev/urandom of=${dir}/4kdata bs=1k count=4
    for i in $(seq 1 $objects)
    do
	rados -p $poolname put obj$i $dir/4kdata
    done

    local PG=$(get_pg $poolname obj1)
    # Remember primary during the backfill
    local primary=$(get_primary $poolname obj1)
    local otherosd=$(get_not_primary $poolname obj1)

    ceph osd set noout
    kill_daemons $dir TERM $otherosd || return 1

    rmobjects=$(expr $objects / 4)
    for i in $(seq 1 $rmobjects)
    do
        rados -p $poolname rm obj$i
    done

    dd if=/dev/urandom of=${dir}/2.5kdata bs=2730 count=1
    for i in $(seq $(expr $rmobjects + 1) $objects)
    do
	rados -p $poolname put obj$i $dir/2.5kdata
    done

    activate_osd $dir $otherosd || return 1

    ceph tell osd.$primary debug kick_recovery_wq 0

    sleep 2

    wait_for_clean || return 1

    delete_pool $poolname
    kill_daemons $dir || return 1
}

main osd-backfill-space "$@"

# Local Variables:
# compile-command: "make -j4 && ../qa/run-standalone.sh osd-backfill-space.sh"
# End:
