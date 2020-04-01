import json
import logging
import time
from io import BytesIO
from textwrap import dedent

from teuthology.orchestra.run import CommandFailedError
from teuthology import misc
from teuthology.orchestra import remote as orchestra_remote
from teuthology.orchestra import run
from teuthology.contextutil import MaxWhileTries
from tasks.cephfs.mount import CephFSMount

log = logging.getLogger(__name__)


UMOUNT_TIMEOUT = 300


class KernelMount(CephFSMount):
    def __init__(self, ctx, test_dir, client_id, client_remote,
                 ipmi_user, ipmi_password, ipmi_domain,
                 client_keyring_path=None):
        super(KernelMount, self).__init__(ctx=ctx, test_dir=test_dir,
            client_id=client_id, client_remote=client_remote,
            client_keyring_path=client_keyring_path)

        self.mounted = False
        self.ipmi_user = ipmi_user
        self.ipmi_password = ipmi_password
        self.ipmi_domain = ipmi_domain

    def get_key_from_keyfile(self):
        with open(self.client_keyring_path, 'r') as keyfile:
            for line in keyfile.read().split('\n'):
                if line.find('key') != -1:
                    return line[line.find('=') + 1 :].strip()

    def mount(self, mntopts=[], createfs=True, check_status=True):
        if client_id is not None:
            self.client_id = client_id
            self.client_keyring_path = client_keyring_path
        self.cephfs_name = cephfs_name
        self.cephfs_mntpt = cephfs_mntpt
        if client_remote is not None:
            self.client_remote = client_remote
        if hostfs_mntpt is not None:
            self.hostfs_mntpt = hostfs_mntpt

        # TODO: don't call setupfs() from within mount().
        if createfs:
            self.setupfs(name=mount_fs_name)

        log.info('Mounting kclient client.{id} at {remote} {mnt}...'.format(
            id=self.client_id, remote=self.client_remote, mnt=self.hostfs_mntpt))

        stderr = BytesIO()
        try:
            self.client_remote.run(args=['mkdir', '-p', self.hostfs_mntpt],
                                   timeout=(5*60), stderr=stderr)
        except CommandFailederror:
            if 'file exists' not in stderr.getvalue().decode().lower():
                raise

        if mount_path is None:
            mount_path = "/"

        if self.client_id is not None:
            opts = 'name=' + self.client_id
        if self.client_keyring_path and self.client_id is not None:
            opts = 'secret=' + self.get_key_from_keyfile()
        opts += ',norequire_active_mds,conf=' + self.config_path
        if mount_fs_name is not None:
            opts += ",mds_namespace={0}".format(mount_fs_name)
        for mount_opt in mount_options :
            opts += ",{0}".format(mount_opt)

        self.run_mount_cmd(opts)

        self.client_remote.run(
            args=['sudo', 'chmod', '1777', self.hostfs_mntpt], timeout=(5*60))

        self.mounted = True

    def run_mount_cmd(self, opts):
        mount_dev = ':' + mount_path
        prefix = ['sudo', 'adjust-ulimits', 'ceph-coverage', self.test_dir + \
                  '/archive/coverage']
        cmdargs = prefix + ['/bin/mount', '-t', 'ceph', mount_dev,
                            self.hostfs_mntpt, '-v', '-o', opts]

        mountcmd_stdout, mountcmd_stderr = BytesIO(), BytesIO()
        try:
            self.client_remote.run(args=cmdargs, timeout=(30*60),
                                   stdout=mountcmd_stdout,
                                    stderr=mountcmd_stderr)
        except CommandFailedError as e:
            if check_status:
                raise
            else:
                return (e, mountcmd_stdout.getvalue().decode(),
                        mountcmd_stderr.getvalue().decode())

    def umount(self, force=False):
        log.debug('Unmounting client client.{id}...'.format(id=self.client_id))

        cmd=['sudo', 'umount', self.hostfs_mntpt]
        if force:
            cmd.append('-f')

        try:
            self.client_remote.run(args=cmd, timeout=(15*60))
        except Exception as e:
            self.client_remote.run(args=[
                'sudo',
                run.Raw('PATH=/usr/sbin:$PATH'),
                'lsof',
                run.Raw(';'),
                'ps', 'auxf',
            ], timeout=(15*60))
            raise e

        rproc = self.client_remote.run(
            args=[
                'rmdir',
                '--',
                self.hostfs_mntpt,
            ],
            wait=False
        )
        run.wait([rproc], UMOUNT_TIMEOUT)
        self.mounted = False

    def umount_wait(self, force=False, require_clean=False, timeout=900,
                    cleanup=True):
        """
        Unlike the fuse client, the kernel client's umount is immediate
        """
        if not self.is_mounted():
            return

        try:
            self.umount(force)
        except (CommandFailedError, MaxWhileTries):
            if not force:
                raise

            self.kill()
            self.kill_cleanup()
            if cleanup:
                self.cleanup()

        self.mounted = False

    def kill(self):
        """
        The Ceph kernel client doesn't have a mechanism to kill itself (doing
        that in side the kernel would be weird anyway), so we reboot the whole node
        to get the same effect.

        We use IPMI to reboot, because we don't want the client to send any
        releases of capabilities.
        """
        con = orchestra_remote.getRemoteConsole(self.client_remote.hostname,
                                                self.ipmi_user,
                                                self.ipmi_password,
                                                self.ipmi_domain)
        con.hard_reset(wait_for_login=False)

        self.mounted = False

        # We need to do a sleep here because we don't know how long it will
        # take for a hard_reset to be effected.
        time.sleep(30)

        try:
            # Wait for node to come back up after reboot
            misc.reconnect(None, 300, [self.client_remote])
        except:
            # attempt to get some useful debug output:
            con = orchestra_remote.getRemoteConsole(self.client_remote.hostname,
                                                    self.ipmi_user,
                                                    self.ipmi_password,
                                                    self.ipmi_domain)
            con.check_status(timeout=60)
            raise

        # Remove mount directory
        self.client_remote.run(args=['uptime'], timeout=10)

    def cleanup(self):
        """
        Remove the mount point.
        """
        if self.mounted:
            raise RuntimeError('Unmount ' + self.hostfs_mntpt + ' before calling '
                               'cleanup().')

        stderr = BytesIO()
        try:
            self.client_remote.run(args=['rmdir', '--', self.hostfs_mntpt],
                cwd=self.test_dir, stderr=stderr, timeout=(60*5),
                check_status=False)
        except CommandFailedError:
            if b'no such file or directory' not in stderr.getvalue().lower():
                raise

    def is_mounted(self):
        return self.mounted

    def wait_until_mounted(self):
        """
        Unlike the fuse client, the kernel client is up and running as soon
        as the initial mount() function returns.
        """
        assert self.mounted

    def teardown(self):
        super(KernelMount, self).teardown()
        if self.mounted:
            self.umount()

    def _find_debug_dir(self):
        """
        Find the debugfs folder for this mount
        """
        pyscript = dedent("""
            import glob
            import os
            import json

            def get_id_to_dir():
                result = {}
                for dir in glob.glob("/sys/kernel/debug/ceph/*"):
                    mds_sessions_lines = open(os.path.join(dir, "mds_sessions")).readlines()
                    client_id = mds_sessions_lines[1].split()[1].strip('"')

                    result[client_id] = dir
                return result

            print(json.dumps(get_id_to_dir()))
            """)

        output = self.client_remote.sh([
            'sudo', 'python3', '-c', pyscript
        ], timeout=(5*60))
        client_id_to_dir = json.loads(output)

        try:
            return client_id_to_dir[self.client_id]
        except KeyError:
            log.error("Client id '{0}' debug dir not found (clients seen were: {1})".format(
                self.client_id, ",".join(client_id_to_dir.keys())
            ))
            raise

    def _read_debug_file(self, filename):
        debug_dir = self._find_debug_dir()

        pyscript = dedent("""
            import os

            print(open(os.path.join("{debug_dir}", "{filename}")).read())
            """).format(debug_dir=debug_dir, filename=filename)

        output = self.client_remote.sh([
            'sudo', 'python3', '-c', pyscript
        ], timeout=(5*60))
        return output

    def get_global_id(self):
        """
        Look up the CephFS client ID for this mount, using debugfs.
        """

        assert self.mounted

        mds_sessions = self._read_debug_file("mds_sessions")
        lines = mds_sessions.split("\n")
        return int(lines[0].split()[1])

    def get_osd_epoch(self):
        """
        Return 2-tuple of osd_epoch, osd_epoch_barrier
        """
        osd_map = self._read_debug_file("osdmap")
        lines = osd_map.split("\n")
        first_line_tokens = lines[0].split()
        epoch, barrier = int(first_line_tokens[1]), int(first_line_tokens[3])

        return epoch, barrier
