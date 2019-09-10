import os
import json
import time
import errno
import random
import signal
import logging

from tasks.cephfs.cephfs_test_case import CephFSTestCase
from teuthology.exceptions import CommandFailedError

log = logging.getLogger(__name__)

def verify_mds_metrics(fs, active_mds_count=1, client_count=1):
    def verify_metrics_cbk(metrics):
        mds_metrics = metrics['metrics']
        if not len(mds_metrics) == active_mds_count + 1: # n active mdss + delayed set
            return False
        fs_status = fs.status()
        ranks = set([info['rank'] for info in fs_status.get_ranks(fs.id)])
        for rank in ranks:
            r = mds_metrics.get("mds.{}".format(rank), None)
            if not r or not len(mds_metrics['delayed_ranks']) == 0:
                return False
        global_metrics = metrics['global_metrics']
        client_metadata = metrics['client_metadata']
        for client in list(client_metadata.keys()):
            if client_metadata[client]['mount_point'] == "N/A":
                del client_metadata[client]
                del global_metrics[client]
        if not len(global_metrics) == client_count or not len(client_metadata) == client_count:
            return False
        return True
    return verify_metrics_cbk

class TestMDSMetrics(CephFSTestCase):
    CLIENTS_REQUIRED = 2
    MDSS_REQUIRED = 3

    TEST_DIR_PERFIX = "test_mds_metrics"

    def setUp(self):
        super(TestMDSMetrics, self).setUp()
        self._start_with_single_active_mds()
        self._enable_mgr_stats_plugin()

    def tearDown(self):
        self._disable_mgr_stats_plugin()
        super(TestMDSMetrics, self).tearDown()

    def _start_with_single_active_mds(self):
        curr_max_mds = self.fs.get_var('max_mds')
        if curr_max_mds > 1:
            self.fs.shrink(1)

    def _fs_perf_stats(self, *args):
        return self.mgr_cluster.mon_manager.raw_cluster_cmd("fs", "perf", "stats", *args)

    def _enable_mgr_stats_plugin(self):
        return self.mgr_cluster.mon_manager.raw_cluster_cmd("mgr", "module", "enable", "stats")

    def _disable_mgr_stats_plugin(self):
        return self.mgr_cluster.mon_manager.raw_cluster_cmd("mgr", "module", "disable", "stats")

    def _spread_directory_on_all_ranks(self, fscid):
        fs_status = self.fs.status()
        ranks = set([info['rank'] for info in fs_status.get_ranks(fscid)])
        # create a per-rank pinned directory
        for rank in ranks:
            dirname = "{0}_{1}".format(TestMDSMetrics.TEST_DIR_PERFIX, rank)
            self.mount_a.run_shell(["mkdir", dirname])
            self.mount_a.setfattr(dirname, "ceph.dir.pin", str(rank))
            log.info("pinning directory {0} to rank {1}".format(dirname, rank))
            for i in range(16):
                filename = "{0}.{1}".format("test", i)
                self.mount_a.write_n_mb(os.path.join(dirname, filename), 1)

    def _do_spread_io(self, fscid):
        # spread readdir I/O
        self.mount_b.run_shell(["find", "."])

    def _do_spread_io_all_clients(self, fscid):
        # spread readdir I/O
        self.mount_a.run_shell(["find", "."])
        self.mount_b.run_shell(["find", "."])

    def _cleanup_test_dirs(self):
        dirnames = self.mount_a.run_shell(["ls"]).stdout.getvalue()
        for dirname in dirnames.split("\n"):
            if dirname.startswith(TestMDSMetrics.TEST_DIR_PERFIX):
                log.info("cleaning directory {}".format(dirname))
                self.mount_a.run_shell(["rm", "-rf", dirname])

    def _get_metrics(self, verifier_callback, trials, *args):
        metrics = None
        done = False
        while not done and trials > 0:
            metrics = json.loads(self._fs_perf_stats(*args))
            done = verifier_callback(metrics)
            time.sleep(1)
            trials -= 1
        # return last fetched metric for examination
        return done, metrics

    # basic check to verify if we get back metrics from each active mds rank

    def test_metrics_from_rank(self):
        # validate
        valid, metrics = self._get_metrics(
            verify_mds_metrics(self.fs, client_count=TestMDSMetrics.CLIENTS_REQUIRED), 30)
        log.debug("metrics={0}".format(metrics))
        self.assertTrue(valid)

    def test_metrics_post_client_disconnection(self):
        # validate
        valid, metrics = self._get_metrics(
            verify_mds_metrics(self.fs, client_count=TestMDSMetrics.CLIENTS_REQUIRED), 30)
        log.debug("metrics={0}".format(metrics))
        self.assertTrue(valid)

        self.mount_a.umount_wait()

        valid, metrics = self._get_metrics(
            verify_mds_metrics(self.fs, client_count=TestMDSMetrics.CLIENTS_REQUIRED - 1), 30)
        log.debug("metrics={0}".format(metrics))
        self.assertTrue(valid)

    def test_metrics_mds_grow(self):
        # validate
        valid, metrics = self._get_metrics(
            verify_mds_metrics(self.fs, client_count=TestMDSMetrics.CLIENTS_REQUIRED), 30)
        log.debug("metrics={0}".format(metrics))
        self.assertTrue(valid)

        # grow the mds cluster
        self.fs.grow(2)

        fscid = self.fs.id
        # spread directory per rank
        self._spread_directory_on_all_ranks(fscid)

        # spread some I/O
        self._do_spread_io(fscid)

        # wait a bit for mgr to get updated metrics
        time.sleep(5)

        # validate
        valid, metrics = self._get_metrics(verify_mds_metrics(
            self.fs, active_mds_count=2, client_count=TestMDSMetrics.CLIENTS_REQUIRED) , 30)
        log.debug("metrics={0}".format(metrics))
        self.assertTrue(valid)

        # cleanup test directories
        self._cleanup_test_dirs()

    def test_metrics_mds_grow_and_shrink(self):
        # validate
        valid, metrics = self._get_metrics(
            verify_mds_metrics(self.fs, client_count=TestMDSMetrics.CLIENTS_REQUIRED), 30)
        log.debug("metrics={0}".format(metrics))
        self.assertTrue(valid)

        # grow the mds cluster
        self.fs.grow(2)

        fscid = self.fs.id
        # spread directory per rank
        self._spread_directory_on_all_ranks(fscid)

        # spread some I/O
        self._do_spread_io(fscid)

        # wait a bit for mgr to get updated metrics
        time.sleep(5)

        # validate
        valid, metrics = self._get_metrics(
            verify_mds_metrics(self.fs, active_mds_count=2, client_count=TestMDSMetrics.CLIENTS_REQUIRED), 30)
        log.debug("metrics={0}".format(metrics))
        self.assertTrue(valid)

        # shrink mds cluster
        self.fs.shrink(1)

        # wait a bit for mgr to get updated metrics
        time.sleep(5)

        # validate
        valid, metrics = self._get_metrics(
            verify_mds_metrics(self.fs, client_count=TestMDSMetrics.CLIENTS_REQUIRED), 30)
        log.debug("metrics={0}".format(metrics))
        self.assertTrue(valid)

        # cleanup test directories
        self._cleanup_test_dirs()

    def test_delayed_metrics(self):
        # validate
        valid, metrics = self._get_metrics(
            verify_mds_metrics(self.fs, client_count=TestMDSMetrics.CLIENTS_REQUIRED), 30)
        log.debug("metrics={0}".format(metrics))
        self.assertTrue(valid)

        # grow the mds cluster
        self.fs.grow(2)

        fscid = self.fs.id
        # spread directory per rank
        self._spread_directory_on_all_ranks(fscid)

        # spread some I/O
        self._do_spread_io(fscid)

        # wait a bit for mgr to get updated metrics
        time.sleep(5)

        # validate
        valid, metrics = self._get_metrics(
            verify_mds_metrics(self.fs, active_mds_count=2, client_count=TestMDSMetrics.CLIENTS_REQUIRED), 30)
        log.debug("metrics={0}".format(metrics))
        self.assertTrue(valid)

        # do not give this mds any chance
        delayed_rank = 1
        mds_id_rank0 = self.fs.get_rank(rank=0)['name']
        mds_id_rank1 = self.fs.get_rank(rank=delayed_rank)['name']

        self.fs.set_inter_mds_block(True, mds_id_rank0, mds_id_rank1)

        def verify_delayed_metrics(metrics):
            mds_metrics = metrics['metrics']
            r = mds_metrics.get("mds.{}".format(delayed_rank), None)
            if not r or not delayed_rank in mds_metrics['delayed_ranks']:
                return False
            return True
        # validate
        valid, metrics = self._get_metrics(verify_delayed_metrics, 30)
        log.debug("metrics={0}".format(metrics))

        self.assertTrue(valid)
        self.fs.set_inter_mds_block(False, mds_id_rank0, mds_id_rank1)

        # validate
        valid, metrics = self._get_metrics(
            verify_mds_metrics(self.fs, active_mds_count=2, client_count=TestMDSMetrics.CLIENTS_REQUIRED), 30)
        log.debug("metrics={0}".format(metrics))
        self.assertTrue(valid)

        # cleanup test directories
        self._cleanup_test_dirs()

    def test_query_mds_filter(self):
        # validate
        valid, metrics = self._get_metrics(
            verify_mds_metrics(self.fs, client_count=TestMDSMetrics.CLIENTS_REQUIRED), 30)
        log.debug("metrics={0}".format(metrics))
        self.assertTrue(valid)

        # grow the mds cluster
        self.fs.grow(2)

        fscid = self.fs.id
        # spread directory per rank
        self._spread_directory_on_all_ranks(fscid)

        # spread some I/O
        self._do_spread_io(fscid)

        # wait a bit for mgr to get updated metrics
        time.sleep(5)

        # validate
        valid, metrics = self._get_metrics(
            verify_mds_metrics(self.fs, active_mds_count=2, client_count=TestMDSMetrics.CLIENTS_REQUIRED), 30)
        log.debug("metrics={0}".format(metrics))
        self.assertTrue(valid)

        # initiate a new query with `--mds_rank` filter and validate if
        # we get metrics *only* from that mds.
        filtered_mds = 1
        client_count = TestMDSMetrics.CLIENTS_REQUIRED
        def verify_filtered_metrics_mds(metrics):
            mds_metrics = metrics['metrics']
            if not len(mds_metrics) == 2: # filtered mds + delayed set
                return False
            r = mds_metrics.get("mds.{}".format(filtered_mds), None)
            if not r or not len(mds_metrics['delayed_ranks']) == 0:
                return False
        global_metrics = metrics['global_metrics']
        client_metadata = metrics['client_metadata']
        for client in list(client_metadata.keys()):
            if client_metadata[client]['mount_point'] == "N/A":
                del client_metadata[client]
                del global_metrics[client]
        if not len(global_metrics) == client_count or not len(client_metadata) == client_count:
            return False
        return True
        valid, metrics = self._get_metrics(
            verify_filtered_metrics_mds, 30, '--mds_rank={}'.format(filtered_mds))
        log.debug("metrics={0}".format(metrics))
        self.assertTrue(valid)

    def test_query_client_filter(self):
        # validate
        valid, metrics = self._get_metrics(
            verify_mds_metrics(self.fs, client_count=TestMDSMetrics.CLIENTS_REQUIRED), 30)
        log.debug("metrics={0}".format(metrics))
        self.assertTrue(valid)

        mds_metrics = metrics['metrics']

        # pick an random client
        client = random.choice(list(mds_metrics['mds.0'].keys()))
        # could have used regex to extract client id
        client_id = (client.split(' ')[0]).split('.')[-1]

        fscid = self.fs.id
        def verify_filtered_metrics_client(metrics):
            mds_metrics = metrics['metrics']
            if not len(mds_metrics) == 2: # 1 active mds + delayed set
                return False
            fs_status = self.fs.status()
            ranks = set([info['rank'] for info in fs_status.get_ranks(fscid)])
            r = mds_metrics.get("mds.0", None)
            if not r or not len(mds_metrics['delayed_ranks']) == 0:
                return False
            if not len(r) == 1 and not client in r:
                return False
            global_metrics = metrics['global_metrics']
            client_metadata = metrics['client_metadata']
            if not len(global_metrics) == 1 or not client in global_metrics:
                return False
            if not len(client_metadata) == 1 or not client in client_metadata:
                return False
            return True
        valid, metrics = self._get_metrics(verify_filtered_metrics_client, 30, '--client_id={}'.format(client_id))
        log.debug("metrics={0}".format(metrics))
        self.assertTrue(valid)

    def test_query_mds_and_client_filter(self):
        # validate
        valid, metrics = self._get_metrics(
            verify_mds_metrics(self.fs, client_count=TestMDSMetrics.CLIENTS_REQUIRED), 30)
        log.debug("metrics={0}".format(metrics))
        self.assertTrue(valid)

        # grow the mds cluster
        self.fs.grow(2)

        fscid = self.fs.id
        # spread directory per rank
        self._spread_directory_on_all_ranks(fscid)

        # spread some I/O
        self._do_spread_io_all_clients(fscid)

        # wait a bit for mgr to get updated metrics
        time.sleep(5)

        # validate
        valid, metrics = self._get_metrics(
            verify_mds_metrics(self.fs, active_mds_count=2, client_count=TestMDSMetrics.CLIENTS_REQUIRED), 30)
        log.debug("metrics={0}".format(metrics))
        self.assertTrue(valid)

        mds_metrics = metrics['metrics']

        # pick an random client
        client = random.choice(list(mds_metrics['mds.1'].keys()))
        # could have used regex to extract client id
        client_id = (client.split(' ')[0]).split('.')[-1]

        fscid = self.fs.id
        filtered_mds = 1
        def verify_filtered_metrics_mds_and_client(metrics):
            mds_metrics = metrics['metrics']
            if not len(mds_metrics) == 2: # filtered mds + delayed set
                return False
            r = mds_metrics.get("mds.{}".format(filtered_mds), None)
            if not r or not len(mds_metrics['delayed_ranks']) == 0:
                return False
            if not len(r) == 1 and not client in r:
                return False
            global_metrics = metrics['global_metrics']
            client_metadata = metrics['client_metadata']
            if not len(global_metrics) == 1 or not client in global_metrics:
                return False
            if not len(client_metadata) == 1 or not client in client_metadata:
                return False
            return True
        valid, metrics = self._get_metrics(verify_filtered_metrics_mds_and_client, 30,
                                           '--mds_rank={}'.format(filtered_mds), '--client_id={}'.format(client_id))
        log.debug("metrics={0}".format(metrics))
        self.assertTrue(valid)
