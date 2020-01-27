from contextlib import contextmanager
from io import BytesIO
import json
import logging
import datetime
import six
import time
from six import StringIO
from textwrap import dedent
import os
from teuthology.orchestra import run
from teuthology.orchestra.run import CommandFailedError, ConnectionLostError
from tasks.cephfs.filesystem import Filesystem

log = logging.getLogger(__name__)


class CephFSMount(object):
    def __init__(self, ctx, test_dir, client_id, client_remote,
                 client_keyring_path=None, hostfs_mntpt=None,
                 cephfs_name=None, cephfs_mntpt=None):
        """
        :param test_dir: Global teuthology test dir
        :param client_id: Client ID, the 'foo' in client.foo
        :param client_keyring_path: path to keyring for given client_id
        :param client_remote: Remote instance for the host where client will
                              run
        :param hostfs_mntpt: Path to directory on the FS on which Ceph FS will
                             be mounted
        :param cephfs_name: Name of Ceph FS to be mounted
        :param cephfs_mntpt: Path to directory inside Ceph FS that will be
                             mounted as root
        """
        self.ctx = ctx
        self.test_dir = test_dir

        self.client_id = client_id
        self.client_keyring_path = client_keyring_path
        self.client_remote = client_remote
        if hostfs_mntpt:
            self.hostfs_mntpt = hostfs_mntpt
            self.hostfs_mntpt_dirname = os.path.basename(self.hostfs_mntpt)
        else:
            self.hostfs_mntpt = os.path.join(self.test_dir,
                                             'mnt.%s' % (self.client_id))
        self.cephfs_name = cephfs_name
        self.cephfs_mntpt = cephfs_mntpt

        self.fs = None
        self.test_files = ['a', 'b', 'c']
        self.background_procs = []

    @property
    def mountpoint(self):
        if self.hostfs_mntpt == None:
            self.hostfs_mntpt= os.path.join(self.test_dir,
                                            self.hostfs_mntpt_dirname)
        return self.hostfs_mntpt

    @mountpoint.setter
    def mountpoint(self, path):
        if not isinstance(path, str):
            raise RuntimeError('path should be of str type.')
        self.hostfs_mntpt = path

    def assert_and_log_minimum_mount_details(self):
        """
        Make sure we have minimum details required for mounting. Ideally, this
        method should be called at the beginning of the mount method.
        """
        log.info('Mounting Ceph FS with client.{id} at {remote} {mnt}...'.format(
                 id=self.client_id, remote=self.client_remote,
                 mnt=self.hostfs_mntpt, cephfs_name=self.cephfs_name))

        if not self.client_id or not self.client_remote or \
           not self.hostfs_mntpt:
            errmsg = ('Mounting CephFS requires that at least following '
                      'details to be provided -\n'
                      '1. the client ID,\n2. the mountpoint and\n'
                      '3. the remote machine where CephFS will be mounted.\n')
            raise RuntimeError(errmsg)

    def is_mounted(self):
        raise NotImplementedError()

    def setupfs(self, name=None):
        if name is None and self.fs is not None:
            # Previous mount existed, reuse the old name
            name = self.fs.name
        self.fs = Filesystem(self.ctx, name=name)
        log.info('Wait for MDS to reach steady state...')
        self.fs.wait_for_daemons()
        log.info('Ready to start {}...'.format(type(self).__name__))

    def mount(self, client_id=None, client_keyring_path=None,
              client_remote=None, cephfs_name=None, cephfs_mntpt=None,
              hostfs_mntpt=None, mntopts=[], createfs=True):
        raise NotImplementedError()

    def umount(self):
        raise NotImplementedError()

    def umount_wait(self, force=False, require_clean=False, timeout=None):
        """

        :param force: Expect that the mount will not shutdown cleanly: kill
                      it hard.
        :param require_clean: Wait for the Ceph client associated with the
                              mount (e.g. ceph-fuse) to terminate, and
                              raise if it doesn't do so cleanly.
        :param timeout: amount of time to be waited for umount command to finish
        :return:
        """
        raise NotImplementedError()

    def _update_attrs(self, client_id, client_keyring_path, client_remote,
                     cephfs_name, cephfs_mntpt, hostfs_mntpt):
        if not (client_id or client_keyring_path or client_remote or
                cephfs_name or cephfs_mntpt or hostfs_mntpt or mntopts or
                createfs):
            raise RuntimeError('remount() was called but no args were passed.')

        if client_id is not None:
            self.client_id = client_id
            self.client_keyring_path = client_keyring_path
        if client_remote is not None:
            self.client_remote = client_remote
        self.cephfs_name = cephfs_name
        self.cephfs_mntpt = cephfs_mntpt
        if hostfs_mntpt is not None:
            self.hostfs_mntpt = hostfs_mntpt

    def remount(self, client_id=None, client_keyring_path=None,
                client_remote=None, hostfs_mntpt=None, cephfs_name=None,
                cephfs_mntpt=None, mntopts=[], createfs=False, wait=False):
        """
        Remount with new client, on new remote, with some other FS or at new
        mountpoint on host FS or mount a different CephFS directory.

        1. Run umount_wait()
        2. Modify object variables if required
        3. Run mount(), do not run setupfs().
        """
        self.umount_wait()
        assert not self.mounted

        return self.update_and_mount(
            client_id=client_id,
            client_keyring_path=client_keyring_path,
            client_remote=client_remote, cephfs_name=cephfs_name,
            cephfs_mntpt=cephfs_mntpt, hostfs_mntpt=hostfs_mntpt,
            mntopts=mntopts, createfs=createfs, check_status=check_status, wait=wait)

    def update_and_mount(self, client_id=None, client_keyring_path=None,
                         client_remote=None, cephfs_name=None,
                         cephfs_mntpt=None, hostfs_mntpt=None, mntopts=[],
                         createfs=False, check_status=True, wait=False):
        self._update_attrs(client_id=client_id,
                          client_keyring_path=client_keyring_path,
                          client_remote=client_remote, cephfs_name=cephfs_name,
                          cephfs_mntpt=cephfs_mntpt, hostfs_mntpt=hostfs_mntpt)

        retval = self.mount(mntopts=mntopts, createfs=createfs)
        # XXX: in case check_status was False and mount command failed.
        if retval:
            return retval
        if wait:
            self.wait_until_mounted()

    def kill_cleanup(self):
        raise NotImplementedError()

    def kill(self):
        raise NotImplementedError()

    def cleanup(self):
        raise NotImplementedError()

    def wait_until_mounted(self):
        raise NotImplementedError()

    def get_keyring_path(self):
        return '/etc/ceph/ceph.client.{id}.keyring'.format(id=self.client_id)

    def get_key_from_keyfile(self):
        # XXX: don't call run_shell(), since CephFS might be unmounted.
        keyring = self.client_remote.run(
            args=['sudo', 'cat', self.client_keyring_path], stdout=StringIO(),
            omit_sudo=False).stdout.getvalue()
        for line in keyring.split('\n'):
            if line.find('key') != -1:
                return line[line.find('=') + 1 : ].strip()

    @property
    def config_path(self):
        """
        Path to ceph.conf: override this if you're not a normal systemwide ceph install
        :return: stringv
        """
        return "/etc/ceph/ceph.conf"

    @contextmanager
    def mounted(self):
        """
        A context manager, from an initially unmounted state, to mount
        this, yield, and then unmount and clean up.
        """
        self.mount()
        self.wait_until_mounted()
        try:
            yield
        finally:
            self.umount_wait()

    def is_blacklisted(self):
        addr = self.get_global_addr()
        blacklist = json.loads(self.fs.mon_manager.raw_cluster_cmd("osd", "blacklist", "ls", "--format=json"))
        for b in blacklist:
            if addr == b["addr"]:
                return True
        return False

    def create_file(self, filename='testfile', dirname=None, user=None,
                    check_status=True):
        assert(self.is_mounted())

        if not os.path.isabs(filename):
            if dirname:
                if os.path.isabs(dirname):
                    path = os.path.join(dirname, filename)
                else:
                    path = os.path.join(self.hostfs_mntpt, dirname, filename)
            else:
                path = os.path.join(self.hostfs_mntpt, filename)
        else:
            path = filename

        if user:
            args = ['sudo', '-u', user, '-s', '/bin/bash', '-c', 'touch ' + path]
        else:
            args = 'touch ' + path

        return self.client_remote.run(args=args, check_status=check_status)

    def create_files(self):
        assert(self.is_mounted())

        for suffix in self.test_files:
            log.info("Creating file {0}".format(suffix))
            self.client_remote.run(args=[
                'sudo', 'touch', os.path.join(self.hostfs_mntpt, suffix)
            ])

    def test_create_file(self, filename='testfile', dirname=None, user=None,
                         check_status=True):
        return self.create_file(filename=filename, dirname=dirname, user=user,
                                check_status=False)

    def check_files(self):
        assert(self.is_mounted())

        for suffix in self.test_files:
            log.info("Checking file {0}".format(suffix))
            r = self.client_remote.run(args=[
                'sudo', 'ls', os.path.join(self.hostfs_mntpt, suffix)
            ], check_status=False)
            if r.exitstatus != 0:
                raise RuntimeError("Expected file {0} not found".format(suffix))

    def create_destroy(self):
        assert(self.is_mounted())

        filename = "{0} {1}".format(datetime.datetime.now(), self.client_id)
        log.debug("Creating test file {0}".format(filename))
        self.client_remote.run(args=[
            'sudo', 'touch', os.path.join(self.hostfs_mntpt, filename)
        ])
        log.debug("Deleting test file {0}".format(filename))
        self.client_remote.run(args=[
            'sudo', 'rm', '-f', os.path.join(self.hostfs_mntpt, filename)
        ])

    def _run_python(self, pyscript, py_version='python3'):
        return self.client_remote.run(
               args=['sudo', 'adjust-ulimits', 'daemon-helper', 'kill',
                     py_version, '-c', pyscript], wait=False, stdin=run.PIPE,
               stdout=StringIO())

    def run_python(self, pyscript, py_version='python3'):
        p = self._run_python(pyscript, py_version)
        p.wait()
        return six.ensure_str(p.stdout.getvalue().strip())

    def run_shell(self, args, wait=True, stdin=None, check_status=True,
                  omit_sudo=True):
        if isinstance(args, str):
            args = args.split()

        args = ["cd", self.mountpoint, run.Raw('&&'), "sudo"] + args
        return self.client_remote.run(args=args, stdout=StringIO(),
                                      stderr=StringIO(), wait=wait,
                                      stdin=stdin, check_status=check_status,
                                      omit_sudo=omit_sudo)

    def open_no_data(self, basename):
        """
        A pure metadata operation
        """
        assert(self.is_mounted())

        path = os.path.join(self.hostfs_mntpt, basename)

        p = self._run_python(dedent(
            """
            f = open("{path}", 'w')
            """.format(path=path)
        ))
        p.wait()

    def open_background(self, basename="background_file", write=True):
        """
        Open a file for writing, then block such that the client
        will hold a capability.

        Don't return until the remote process has got as far as opening
        the file, then return the RemoteProcess instance.
        """
        assert(self.is_mounted())

        path = os.path.join(self.hostfs_mntpt, basename)

        if write:
            pyscript = dedent("""
                import time

                with open("{path}", 'w') as f:
                    f.write('content')
                    f.flush()
                    f.write('content2')
                    while True:
                        time.sleep(1)
                """).format(path=path)
        else:
            pyscript = dedent("""
                import time

                with open("{path}", 'r') as f:
                    while True:
                        time.sleep(1)
                """).format(path=path)

        rproc = self._run_python(pyscript)
        self.background_procs.append(rproc)

        # This wait would not be sufficient if the file had already
        # existed, but it's simple and in practice users of open_background
        # are not using it on existing files.
        self.wait_for_visible(basename)

        return rproc

    def wait_for_dir_empty(self, dirname, timeout=30):
        i = 0
        dirpath = os.path.join(self.hostfs_mntpt, dirname)
        while i < timeout:
            nr_entries = int(self.getfattr(dirpath, "ceph.dir.entries"))
            if nr_entries == 0:
                log.debug("Directory {0} seen empty from {1} after {2}s ".format(
                    dirname, self.client_id, i))
                return
            else:
                time.sleep(1)
                i += 1

        raise RuntimeError("Timed out after {0}s waiting for {1} to become empty from {2}".format(
            i, dirname, self.client_id))

    def wait_for_visible(self, basename="background_file", timeout=30):
        i = 0
        while i < timeout:
            r = self.client_remote.run(args=[
                'sudo', 'ls', os.path.join(self.hostfs_mntpt, basename)
            ], check_status=False)
            if r.exitstatus == 0:
                log.debug("File {0} became visible from {1} after {2}s".format(
                    basename, self.client_id, i))
                return
            else:
                time.sleep(1)
                i += 1

        raise RuntimeError("Timed out after {0}s waiting for {1} to become visible from {2}".format(
            i, basename, self.client_id))

    def lock_background(self, basename="background_file", do_flock=True):
        """
        Open and lock a files for writing, hold the lock in a background process
        """
        assert(self.is_mounted())

        path = os.path.join(self.hostfs_mntpt, basename)

        script_builder = """
            import time
            import fcntl
            import struct"""
        if do_flock:
            script_builder += """
            f1 = open("{path}-1", 'w')
            fcntl.flock(f1, fcntl.LOCK_EX | fcntl.LOCK_NB)"""
        script_builder += """
            f2 = open("{path}-2", 'w')
            lockdata = struct.pack('hhllhh', fcntl.F_WRLCK, 0, 0, 0, 0, 0)
            fcntl.fcntl(f2, fcntl.F_SETLK, lockdata)
            while True:
                time.sleep(1)
            """

        pyscript = dedent(script_builder).format(path=path)

        log.info("lock_background file {0}".format(basename))
        rproc = self._run_python(pyscript)
        self.background_procs.append(rproc)
        return rproc

    def lock_and_release(self, basename="background_file"):
        assert(self.is_mounted())

        path = os.path.join(self.hostfs_mntpt, basename)

        script = """
            import time
            import fcntl
            import struct
            f1 = open("{path}-1", 'w')
            fcntl.flock(f1, fcntl.LOCK_EX)
            f2 = open("{path}-2", 'w')
            lockdata = struct.pack('hhllhh', fcntl.F_WRLCK, 0, 0, 0, 0, 0)
            fcntl.fcntl(f2, fcntl.F_SETLK, lockdata)
            """
        pyscript = dedent(script).format(path=path)

        log.info("lock_and_release file {0}".format(basename))
        return self._run_python(pyscript)

    def check_filelock(self, basename="background_file", do_flock=True):
        assert(self.is_mounted())

        path = os.path.join(self.hostfs_mntpt, basename)

        script_builder = """
            import fcntl
            import errno
            import struct"""
        if do_flock:
            script_builder += """
            f1 = open("{path}-1", 'r')
            try:
                fcntl.flock(f1, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except IOError as e:
                if e.errno == errno.EAGAIN:
                    pass
            else:
                raise RuntimeError("flock on file {path}-1 not found")"""
        script_builder += """
            f2 = open("{path}-2", 'r')
            try:
                lockdata = struct.pack('hhllhh', fcntl.F_WRLCK, 0, 0, 0, 0, 0)
                fcntl.fcntl(f2, fcntl.F_SETLK, lockdata)
            except IOError as e:
                if e.errno == errno.EAGAIN:
                    pass
            else:
                raise RuntimeError("posix lock on file {path}-2 not found")
            """
        pyscript = dedent(script_builder).format(path=path)

        log.info("check lock on file {0}".format(basename))
        self.client_remote.run(args=[
            'sudo', 'python3', '-c', pyscript
        ])

    def write_background(self, basename="background_file", loop=False):
        """
        Open a file for writing, complete as soon as you can
        :param basename:
        :return:
        """
        assert(self.is_mounted())

        path = os.path.join(self.hostfs_mntpt, basename)

        pyscript = dedent("""
            import os
            import time

            fd = os.open("{path}", os.O_RDWR | os.O_CREAT, 0o644)
            try:
                while True:
                    os.write(fd, b'content')
                    time.sleep(1)
                    if not {loop}:
                        break
            except IOError as e:
                pass
            os.close(fd)
            """).format(path=path, loop=str(loop))

        rproc = self._run_python(pyscript)
        self.background_procs.append(rproc)
        return rproc

    def write_n_mb(self, filename, n_mb, seek=0, wait=True):
        """
        Write the requested number of megabytes to a file
        """
        assert(self.is_mounted())

        return self.run_shell(["dd", "if=/dev/urandom", "of={0}".format(filename),
                               "bs=1M", "conv=fdatasync",
                               "count={0}".format(n_mb),
                               "seek={0}".format(seek)
                               ], wait=wait)

    def write_test_pattern(self, filename, size):
        log.info("Writing {0} bytes to {1}".format(size, filename))
        return self.run_python(dedent("""
            import zlib
            path = "{path}"
            with open(path, 'w') as f:
                for i in range(0, {size}):
                    val = zlib.crc32(str(i).encode('utf-8')) & 7
                    f.write(chr(val))
        """.format(
            path=os.path.join(self.hostfs_mntpt, filename),
            size=size
        )))

    def validate_test_pattern(self, filename, size):
        log.info("Validating {0} bytes from {1}".format(size, filename))
        return self.run_python(dedent("""
            import zlib
            path = "{path}"
            with open(path, 'r') as f:
                bytes = f.read()
            if len(bytes) != {size}:
                raise RuntimeError("Bad length {{0}} vs. expected {{1}}".format(
                    len(bytes), {size}
                ))
            for i, b in enumerate(bytes):
                val = zlib.crc32(str(i).encode('utf-8')) & 7
                if b != chr(val):
                    raise RuntimeError("Bad data at offset {{0}}".format(i))
        """.format(
            path=os.path.join(self.hostfs_mntpt, filename),
            size=size
        )))

    def open_n_background(self, fs_path, count):
        """
        Open N files for writing, hold them open in a background process

        :param fs_path: Path relative to CephFS root, e.g. "foo/bar"
        :return: a RemoteProcess
        """
        assert(self.is_mounted())

        abs_path = os.path.join(self.hostfs_mntpt, fs_path)

        pyscript = dedent("""
            import sys
            import time
            import os

            n = {count}
            abs_path = "{abs_path}"

            if not os.path.exists(os.path.dirname(abs_path)):
                os.makedirs(os.path.dirname(abs_path))

            handles = []
            for i in range(0, n):
                fname = "{{0}}_{{1}}".format(abs_path, i)
                handles.append(open(fname, 'w'))

            while True:
                time.sleep(1)
            """).format(abs_path=abs_path, count=count)

        rproc = self._run_python(pyscript)
        self.background_procs.append(rproc)
        return rproc

    def create_n_files(self, fs_path, count, sync=False):
        assert(self.is_mounted())

        abs_path = os.path.join(self.hostfs_mntpt, fs_path)

        pyscript = dedent("""
            import sys
            import time
            import os

            n = {count}
            abs_path = "{abs_path}"

            if not os.path.exists(os.path.dirname(abs_path)):
                os.makedirs(os.path.dirname(abs_path))

            for i in range(0, n):
                fname = "{{0}}_{{1}}".format(abs_path, i)
                with open(fname, 'w') as f:
                    f.write('content')
                    if {sync}:
                        f.flush()
                        os.fsync(f.fileno())
            """).format(abs_path=abs_path, count=count, sync=str(sync))

        self.run_python(pyscript)

    def teardown(self):
        for p in self.background_procs:
            log.info("Terminating background process")
            self._kill_background(p)

        self.background_procs = []

    def _kill_background(self, p):
        if p.stdin:
            p.stdin.close()
            try:
                p.wait()
            except (CommandFailedError, ConnectionLostError):
                pass

    def kill_background(self, p):
        """
        For a process that was returned by one of the _background member functions,
        kill it hard.
        """
        self._kill_background(p)
        self.background_procs.remove(p)

    def send_signal(self, signal):
        signal = signal.lower()
        if signal.lower() not in ['sigstop', 'sigcont', 'sigterm', 'sigkill']:
            raise NotImplementedError

        self.client_remote.run(args=['sudo', 'kill', '-{0}'.format(signal),
                                self.client_pid], omit_sudo=False)

    def get_global_id(self):
        raise NotImplementedError()

    def get_global_inst(self):
        raise NotImplementedError()

    def get_global_addr(self):
        raise NotImplementedError()

    def get_osd_epoch(self):
        raise NotImplementedError()

    def lstat(self, fs_path, follow_symlinks=False, wait=True):
        return self.stat(fs_path, follow_symlinks=False, wait=True)

    def stat(self, fs_path, follow_symlinks=True, wait=True):
        """
        stat a file, and return the result as a dictionary like this:
        {
          "st_ctime": 1414161137.0,
          "st_mtime": 1414161137.0,
          "st_nlink": 33,
          "st_gid": 0,
          "st_dev": 16777218,
          "st_size": 1190,
          "st_ino": 2,
          "st_uid": 0,
          "st_mode": 16877,
          "st_atime": 1431520593.0
        }

        Raises exception on absent file.
        """
        abs_path = os.path.join(self.hostfs_mntpt, fs_path)
        if follow_symlinks:
            stat_call = "os.stat('" + abs_path + "')"
        else:
            stat_call = "os.lstat('" + abs_path + "')"

        pyscript = dedent("""
            import os
            import stat
            import json
            import sys

            try:
                s = {stat_call}
            except OSError as e:
                sys.exit(e.errno)

            attrs = ["st_mode", "st_ino", "st_dev", "st_nlink", "st_uid", "st_gid", "st_size", "st_atime", "st_mtime", "st_ctime"]
            print(json.dumps(
                dict([(a, getattr(s, a)) for a in attrs]),
                indent=2))
            """).format(stat_call=stat_call)
        proc = self._run_python(pyscript)
        if wait:
            proc.wait()
            return json.loads(proc.stdout.getvalue().strip())
        else:
            return proc

    def touch(self, fs_path):
        """
        Create a dentry if it doesn't already exist.  This python
        implementation exists because the usual command line tool doesn't
        pass through error codes like EIO.

        :param fs_path:
        :return:
        """
        abs_path = os.path.join(self.hostfs_mntpt, fs_path)
        pyscript = dedent("""
            import sys
            import errno

            try:
                f = open("{path}", "w")
                f.close()
            except IOError as e:
                sys.exit(errno.EIO)
            """).format(path=abs_path)
        proc = self._run_python(pyscript)
        proc.wait()

    def path_to_ino(self, fs_path, follow_symlinks=True):
        abs_path = os.path.join(self.hostfs_mntpt, fs_path)

        if follow_symlinks:
            pyscript = dedent("""
                import os
                import stat

                print(os.stat("{path}").st_ino)
                """).format(path=abs_path)
        else:
            pyscript = dedent("""
                import os
                import stat

                print(os.lstat("{path}").st_ino)
                """).format(path=abs_path)

        proc = self._run_python(pyscript)
        proc.wait()
        return int(proc.stdout.getvalue().strip())

    def path_to_nlink(self, fs_path):
        abs_path = os.path.join(self.hostfs_mntpt, fs_path)

        pyscript = dedent("""
            import os
            import stat

            print(os.stat("{path}").st_nlink)
            """).format(path=abs_path)

        proc = self._run_python(pyscript)
        proc.wait()
        return int(proc.stdout.getvalue().strip())

    def ls(self, path=None):
        """
        Wrap ls: return a list of strings
        """
        cmd = ["ls"]
        if path:
            cmd.append(path)

        ls_text = self.run_shell(cmd).stdout.getvalue().strip()

        if ls_text:
            return ls_text.split("\n")
        else:
            # Special case because otherwise split on empty string
            # gives you [''] instead of []
            return []

    def setfattr(self, path, key, val):
        """
        Wrap setfattr.

        :param path: relative to mount point
        :param key: xattr name
        :param val: xattr value
        :return: None
        """
        self.run_shell(["setfattr", "-n", key, "-v", val, path])

    def getfattr(self, path, attr):
        """
        Wrap getfattr: return the values of a named xattr on one file, or
        None if the attribute is not found.

        :return: a string
        """
        p = self.run_shell(["getfattr", "--only-values", "-n", attr, path], wait=False)
        try:
            p.wait()
        except CommandFailedError as e:
            if e.exitstatus == 1 and "No such attribute" in p.stderr.getvalue():
                return None
            else:
                raise

        return p.stdout.getvalue()

    def df(self):
        """
        Wrap df: return a dict of usage fields in bytes
        """

        p = self.run_shell(["df", "-B1", "."])
        lines = p.stdout.getvalue().strip().split("\n")
        fs, total, used, avail = lines[1].split()[:4]
        log.warn(lines)

        return {
            "total": int(total),
            "used": int(used),
            "available": int(avail)
        }
