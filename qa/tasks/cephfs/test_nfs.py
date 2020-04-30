import os
import json
import time
import errno
import random
import logging
import collections

from tasks.mgr.mgr_test_case import MgrTestCase
from teuthology.exceptions import CommandFailedError

log = logging.getLogger(__name__)

class TestNFS(MGRTestCase):
    MGR_REQUIRED = 1

    def _nfs_cmd(self, *args):
        return self.mgr_cluster.mon_manager.raw_cluster_cmd("nfs", *args)

    def _orch_cmd(self, *args):
        return self.mgr_cluster.mon_manager.raw_cluster_cmd("orch", *args)

    def setUp(self):
        super(TestNFS, self).setUp()

        self.cluster_id = "test"
        self.export_type = "cephfs"
        self.pseudo_path = "/cephfs"

    def test_create_cluster(self):
        nfs_output = self._nfs_cmd("cluster", "create", self.export_type, self.cluster_id)
        orch_output = self._orch_cmd("ls")
        log.info("The Orch Output is {}".format(orch_output))
        log.info("The NFS Output is {}".format(nfs_output))
