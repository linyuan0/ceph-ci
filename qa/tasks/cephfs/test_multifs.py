"""
Test for Ceph clusters with multiple FSs.
"""
import logging

from os.path import join as os_path_join
from six import ensure_str
from io import BytesIO

from tasks.cephfs.mount import CephFSMount
from tasks.cephfs.cephfs_test_case import CephFSTestCase
from tasks.cephfs.filesystem import Filesystem

from teuthology.misc import sudo_write_file
from teuthology.orchestra.run import CommandFailedError
from teuthology.orchestra.run import Raw


log = logging.getLogger(__name__)


class MountDetails():

    def __init__(self, client_id, client_keyring_path, client_remote,
                 cephfs_name, cephfs_mntpt, hostfs_mntpt):
        self.client_id = client_id
        self.client_keyring_path = client_keyring_path
        self.client_remote = client_remote
        self.cephfs_name = cephfs_name
        self.cephfs_mntpt = cephfs_mntpt
        self.hostfs_mntpt = hostfs_mntpt

    def restore(self, mntobj):
        mntobj.client_id = self.client_id
        mntobj.client_keyring_path = self.client_keyring_path
        mntobj.client_remote = self.client_remote
        mntobj.cephfs_name = self.cephfs_name
        mntobj.cephfs_mntpt = self.cephfs_mntpt
        mntobj.hostfs_mntpt = self.hostfs_mntpt


class TestMultiFS(CephFSTestCase):
    # one dedicated and one standby for each FS
    MDSS_REQUIRED = 2
    CLIENTS_REQUIRED = 2

    def setUp(self):
        super(TestMultiFS, self).setUp()

        # XXX: saving mount details that were created by CephFSTestCase.setUp()
        # so that these details restored later to ensure clean setup and
        # teardown for upcoming tests.
        self.mount_details = [
            MountDetails(
                self.mount_a.client_id, self.mount_a.client_keyring_path,
                self.mount_a.client_remote, self.mount_a.cephfs_name,
                self.mount_a.cephfs_mntpt, self.mount_a.hostfs_mntpt),
            MountDetails(
                self.mount_b.client_id, self.mount_b.client_keyring_path,
                self.mount_b.client_remote, self.mount_b.cephfs_name,
                self.mount_b.cephfs_mntpt, self.mount_b.hostfs_mntpt)]

        self.fs1 = self.fs
        self.enable_multifs()
        self.fs2 = self.mds_cluster.newfs(name='cephfs2', create=True)

        # we'll reassign caps to client.1 so that it can operate with cephfs2
        self.fs.mon_manager.raw_cluster_cmd(
            'auth', 'caps', 'client.' + self.mount_b.client_id, 'mon',
            'allow r', 'osd', 'allow rw pool='+self.fs2.get_data_pool_name(),
            'mds', 'allow')
        self.mount_b.remount(cephfs_name=self.fs2.name)

    def tearDown(self):
        self.mount_a.umount_wait()
        self.mount_b.umount_wait()

        self.mount_details[0].restore(self.mount_a)
        self.mount_details[1].restore(self.mount_b)

    def conduct_pos_test_for_read_caps(self, filepaths, filedata, mounts):
        for mount in mounts:
            for path, data in zip(filepaths, filedata):
                # XXX: conduct tests only if path belongs to current mount; in
                # teuth tests client are located on same machines.
                if path.find(mount.hostfs_mntpt) != -1:
                    contents = mount.read_file(path)
                    self.assertEqual(data, contents)

    def conduct_pos_test_for_write_caps(self, filepaths, mounts):
        filedata = ('some new data on first fs', 'some new data on second fs')

        for mount in mounts:
            for path, data in zip(filepaths, filedata):
                if path.find(mount.hostfs_mntpt) != -1:
                    # test that write was successful
                    proc = mount.write_file(path=path, data=data)
                    self.assertEqual(proc.returncode, 0)
                    # verify that contents written was same as the one that was
                    # intended
                    contents1 = mount.read_file(path=path)
                    self.assertEqual(data, contents1)

    def conduct_neg_test_for_write_caps(self, filepaths, mounts):
        cmdargs = ['echo', 'some random data', Raw('|'), 'sudo', 'tee']

        for mount in mounts:
            for path in filepaths:
                if path.find(mount.hostfs_mntpt) != -1:
                    cmdargs.append(path)
                    mount.negtestcmd(args=cmdargs, retval=1,
                                     errmsg='permission denied')


class TestCmdFsAuth(TestMultiFS):
    client_id = 'someuser'
    client_name = 'client.' + client_id

    def tearDown(self):
        self.mount_a.umount_wait()
        self.fs.mon_manager.raw_cluster_cmd('auth', 'rm', 'client.someuser')

        super(type(self), self).tearDown()

    def setup_test_env(self, cap):
        filedata = 'some data on fs 1'
        filename = 'file_on_fs1'
        filepath = os_path_join(self.mount_a.hostfs_mntpt, filename)
        self.mount_a.write_file(filepath, filedata)

        keyring = self.run_fs_auth(self.fs.name, self.client_id, '/',cap)
        keyring_path = self.mount_a.run_shell(args=['mktemp']).stdout.\
            getvalue().strip()
        sudo_write_file(self.mount_a.client_remote, keyring_path, keyring)
        self.mount_a.remount(client_id=self.client_id,
                             client_keyring_path=keyring_path,
                             cephfs_name=self.fs.name, cephfs_mntpt = '/',
                             createfs=False)

        if not isinstance(filepath, tuple):
            filepaths = (filepath, )
        if not isinstance(filedata, tuple):
            filedata = (filedata, )
        mounts = (self.mount_a, )

        return filepaths, filedata, mounts

    def test_r(self):
        cap = 'r'
        filepaths, filedata, mounts = self.setup_test_env(cap)

        self.conduct_pos_test_for_read_caps(filepaths, filedata, mounts)
        self.conduct_neg_test_for_write_caps(filepaths, mounts)

    def test_rw(self):
        cap = 'rw'
        filepaths, filedata, mounts = self.setup_test_env(cap)

        self.conduct_pos_test_for_read_caps(filepaths, filedata, mounts)
        self.conduct_pos_test_for_write_caps(filepaths, mounts)


#TODO: add tests for capsecs 'p' and 's'.
class TestMDSCaps(TestMultiFS):
    """
    0. Have 2 FSs on Ceph cluster.
    1. Create new files on both FSs.
    2. Create a new client that has authorization for both FSs.
    3. Remount the current mounts with this new client.
    4. Test read and write on both FS.
    5. Teardown and set up again.
    6. Repeat 1-5 for all possible combinations produced by read/write
       modes, fsids and paths.
    """
    client_id = 'someuser'
    client_name = 'client.' + client_id

    def tearDown(self):
        self.mount_a.umount_wait()
        self.mount_b.umount_wait()

        self.fs.mon_manager.raw_cluster_cmd('auth', 'rm', 'client.someuser')

        super(type(self), self).tearDown()

    def test_rw_with_fsid_and_no_path_in_cap(self):
        filepaths, filedata, mounts = self.setup_test_env(perm='rw',
                                                          fsid=True)

        self.conduct_pos_test_for_read_caps(filepaths, filedata, mounts)
        self.conduct_pos_test_for_write_caps(filepaths, mounts)

    def test_r_with_fsid_and_no_path_in_cap(self):
        filepaths, filedata, mounts = self.setup_test_env(perm='r',
                                                          fsid=True)

        self.conduct_pos_test_for_read_caps(filepaths, filedata, mounts)
        self.conduct_neg_test_for_write_caps(filepaths, mounts)

    def test_rw_with_fsid_and_path_in_cap(self):
        filepaths, filedata, mounts = self.setup_test_env(
            perm='rw', fsid=True, cephfs_mntpt='dir1')

        self.conduct_pos_test_for_read_caps(filepaths, filedata, mounts)
        self.conduct_pos_test_for_write_caps(filepaths, mounts)

    def test_r_with_fsid_and_path_in_cap(self):
        filepaths, filedata, mounts = self.setup_test_env(
            perm='r', fsid=True, cephfs_mntpt='dir1')

        self.conduct_pos_test_for_read_caps(filepaths, filedata, mounts)
        self.conduct_neg_test_for_write_caps(filepaths, mounts)

    def test_rw_with_no_fsid_and_path_in_cap(self):
        filepaths, filedata, mounts = self.setup_test_env(perm='rw',
                                                          cephfs_mntpt='dir1')

        self.conduct_pos_test_for_read_caps(filepaths, filedata, mounts)
        self.conduct_pos_test_for_write_caps(filepaths, mounts)

    def test_r_with_no_fsid_and_path_in_cap(self):
        filepaths, filedata, mounts = self.setup_test_env(perm='r',
                                                          cephfs_mntpt='dir1')

        self.conduct_pos_test_for_read_caps(filepaths, filedata, mounts)
        self.conduct_neg_test_for_write_caps(filepaths, mounts)

    def test_rw_with_no_fsid_and_no_path(self):
        filepaths, filedata, mounts = self.setup_test_env(perm='rw')

        self.conduct_pos_test_for_read_caps(filepaths, filedata, mounts)
        self.conduct_pos_test_for_write_caps(filepaths, mounts)

    def test_r_with_no_fsid_and_no_path(self):
        filepaths, filedata, mounts = self.setup_test_env(perm='r')

        self.conduct_pos_test_for_read_caps(filepaths, filedata, mounts)
        self.conduct_neg_test_for_write_caps(filepaths, mounts)

    def setup_test_env(self, perm, fsid=False, cephfs_mntpt='/'):
        """
        Creates the cap string, files on both the FSs and then creates the
        new client with the cap and remounts both the FSs with newly created
        client.
        """
        filenames = ('file_on_fs1', 'file_on_fs2')
        filedata = ('some data on first fs', 'some data on second fs')
        mounts = (self.mount_a, self.mount_b)
        self.setup_fs_contents(cephfs_mntpt, filenames, filedata)

        keyrings = self.create_client(perm, fsid, cephfs_mntpt)
        filepaths = self.create_and_remount_with_new_client(
            cephfs_mntpt, filenames, keyrings)

        return filepaths, filedata, mounts

    def create_client(self, perm, fsid, cephfs_mntpt):
        moncap = 'allow r'
        osdcap = ('allow {perm} tag cephfs data={cephfs1_name}, '
                  'allow {perm} tag cephfs data={cephfs2_name}'.format(
                  perm=perm, cephfs1_name=self.fs1.name,
                  cephfs2_name=self.fs2.name))

        if fsid:
            if cephfs_mntpt == '/':
                mdscap = ('allow {perm} fsid={cephfs1_id}, '
                          'allow {perm} fsid={cephfs2_id}'.format(
                          perm=perm, cephfs1_id=self.fs1.id,
                          cephfs2_id=self.fs2.id))
            else:
                mdscap = ('allow {perm} fsid={cephfs1_id} path=/{cephfs_mntpt}, '
                          'allow {perm} fsid={cephfs2_id} '
                          'path=/{cephfs_mntpt}'.format(
                          perm=perm, cephfs1_id=self.fs1.id,
                          cephfs2_id=self.fs2.id, cephfs_mntpt=cephfs_mntpt))
        else:
            if cephfs_mntpt == '/':
                mdscap = 'allow ' + perm
            else:
                mdscap = 'allow {} path=/{}'.format(perm, cephfs_mntpt)

        self.fs.mon_manager.raw_cluster_cmd('auth', 'add', self.client_name,
            'mon', moncap, 'mds', mdscap, 'osd', osdcap)
        keyring = self.fs.mon_manager.raw_cluster_cmd('auth', 'get',
            self.client_name)

        keyring_path_remote1 = self.mount_a.run_shell(args=['mktemp']).\
            stdout.getvalue().strip()
        sudo_write_file(self.mount_a.client_remote, keyring_path_remote1,
                        keyring)

        keyring_path_remote2 = self.mount_a.run_shell(args=['mktemp']).\
            stdout.getvalue().strip()
        sudo_write_file(self.mount_b.client_remote, keyring_path_remote2,
                        keyring)

        return [keyring_path_remote1, keyring_path_remote2]

    def setup_fs_contents(self, cephfs_mntpt, filenames, filedata):
        if isinstance(cephfs_mntpt, str) and cephfs_mntpt != '/' :
            self.mount_a.run_shell(args=['mkdir', cephfs_mntpt])
            filepath1 = os_path_join(self.mount_a.hostfs_mntpt, cephfs_mntpt,
                                     filenames[0])

            self.mount_b.run_shell(args=['mkdir', cephfs_mntpt])
            filepath2 = os_path_join(self.mount_b.hostfs_mntpt, cephfs_mntpt,
                                     filenames[1])
        else:
            filepath1 = os_path_join(self.mount_a.hostfs_mntpt, filenames[0])
            filepath2 = os_path_join(self.mount_b.hostfs_mntpt, filenames[1])

        self.mount_a.write_file(path=filepath1, data=filedata[0])
        self.mount_b.write_file(path=filepath2, data=filedata[1])

    def create_and_remount_with_new_client(self, cephfs_mntpt, filenames,
                                           keyrings):
        if isinstance(cephfs_mntpt, str) and cephfs_mntpt != '/' :
            cephfs_mntpt = '/' + cephfs_mntpt

        self.mount_a.remount(client_id=self.client_id,
                             client_keyring_path=keyrings[0],
                             client_remote=self.mount_a.client_remote,
                             cephfs_name=self.fs1.name,
                             cephfs_mntpt=cephfs_mntpt,
                             hostfs_mntpt=self.mount_a.hostfs_mntpt,
                             check_status=False, wait=True)
        self.mount_b.remount(client_id=self.client_id,
                             client_keyring_path=keyrings[1],
                             client_remote=self.mount_b.client_remote,
                             cephfs_name=self.fs2.name,
                             cephfs_mntpt=cephfs_mntpt,
                             hostfs_mntpt=self.mount_b.hostfs_mntpt,
                             check_status=False, wait=True)

        return (os_path_join(self.mount_a.hostfs_mntpt, filenames[0]),
                os_path_join(self.mount_b.hostfs_mntpt, filenames[1]))


class TestMONCaps(TestMultiFS):
    client_id = 'someuser'
    client_name = 'client.' + client_id

    def test_moncap_with_one_fsid(self):
        moncap = 'allow rw fsid=' + str(self.fs1.id)
        keyring_path = self.create_client_and_get_keyring(moncap)

        fss = self.fs.mon_manager.raw_cluster_cmd(
            'fs', 'ls', '--id', self.client_id, '-k', keyring_path)
        self.assertIn('name: ' + self.fs1.name, fss)
        self.assertNotIn('name: ' + self.fs2.name, fss)

    def test_moncap_with_multiple_fsids(self):
        moncap = 'allow rw fsid=%s, allow rw fsid=%s' % (self.fs1.id,
                                                         self.fs2.id)
        self.run_test_client_with_multiple_mon_cap(moncap)

    def test_moncap_with_blanket_allow(self):
        self.run_test_client_with_multiple_mon_cap('allow rw')

    def run_test_client_with_multiple_mon_cap(self, moncap):
        keyring_path = self.create_client_and_get_keyring(moncap)

        fss = self.fs.mon_manager.raw_cluster_cmd(
            'fs', 'ls', '--id', self.client_id, '-k', keyring_path)
        self.assertIn('name: ' + self.fs1.name, fss)
        self.assertIn('name: ' + self.fs2.name, fss)

    def create_client_and_get_keyring(self, moncap):
        self.fs.mon_manager.raw_cluster_cmd('auth', 'add', self.client_name,
                                            'mon', moncap)

        keyring = self.fs.mon_manager.raw_cluster_cmd(
            'auth', 'get', self.client_name)
        keyring_path = self.fs.admin_remote.run(args=['mktemp'],
             stdout=BytesIO()).stdout.getvalue().decode().strip()
        sudo_write_file(self.fs.admin_remote, keyring_path, keyring)

        return keyring_path


class TestClientsWithoutAuth(TestMultiFS):
    client_id = 'someuser'
    client_name = 'client.' + client_id

    def tearDown(self):
        self.fs.mon_manager.raw_cluster_cmd('auth', 'rm', self.client_name)
        super(type(self), self).tearDown()

    def test_mount(self):
        keyring = self.run_fs_auth(self.fs2.name, self.client_id, '/', 'rw')
        keyring_path = self.mount_a.run_shell(args=['mktemp']).\
            stdout.getvalue().strip()
        sudo_write_file(self.mount_a.client_remote, keyring_path, keyring)

        retval = self.mount_a.remount(
            client_id=self.client_id, client_keyring_path=keyring_path,
            cephfs_name=self.fs1.name, cephfs_mntpt='/', check_status=False)
        self.assertIsInstance(retval, tuple)
        self.assertEqual(len(retval), 3)
        self.assertIsInstance(retval[0], CommandFailedError)
        if 'kernel' in str(type(self.mount_a)).lower():
            self.assertIn('permission denied', retval[2].lower())
        elif 'fuse' in str(type(self.mount_a)).lower():
            self.assertIn('operation not permitted', retval[2].lower())
        else:
            # control should never reach this point
            assert False
