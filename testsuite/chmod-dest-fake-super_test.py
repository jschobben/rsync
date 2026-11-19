#!/usr/bin/env python3
"""Test --chmod-dest with receiver-side --fake-super.

The destination's real modes must be restrictive, while the original source
modes remain in the fake-super %stat xattr and can be restored by a later
fake-super send.  The source must not acquire rsync metadata xattrs.
"""

import errno
import os
import platform
import shlex
import stat
import subprocess

from rsyncfns import (
    FROMDIR, SCRATCHDIR, RSYNC_PREFIX,
    makepath, rmtree, rsync_argv, test_fail, test_skipped,
    xattrs_supported,
)

if platform.system() != 'Linux':
    test_skipped("this test checks Linux user.rsync.%stat xattrs")
if not xattrs_supported():
    test_skipped("xattrs are not supported")

src = SCRATCHDIR / 'chmod-dest-source'
dst = SCRATCHDIR / 'chmod-dest-fakesuper'
restored = SCRATCHDIR / 'chmod-dest-restored'
bad = SCRATCHDIR / 'chmod-dest-without-fakesuper'
for path in (src, dst, restored, bad):
    rmtree(path)
makepath(src)

(src / 'plain').write_text('plain file\n')
(src / 'executable').write_text('executable file\n')
(src / 'setuid').write_text('setuid file\n')
(src / 'subdir').mkdir()
(src / 'subdir' / 'nested').write_text('nested file\n')

modes = {
    'plain': 0o644,
    'executable': 0o751,
    'setuid': 0o4755,
    'subdir': 0o751,
    'subdir/nested': 0o640,
}
for name, mode in modes.items():
    os.chmod(src / name, mode)

stat_attr = 'user.' + RSYNC_PREFIX + '.%stat'


def make_local_fake_super_rsh():
    wrapper = SCRATCHDIR / 'local-fake-super-rsh'
    rsync = rsync_argv()[0]
    wrapper.write_text("""#!/bin/sh
rsync=$1
shift
shift
shift
exec "$rsync" --fake-super "$@"
""")
    wrapper.chmod(0o755)
    return wrapper


def run(args, frm, to, *, ok=True, env=None):
    proc = subprocess.run(
        rsync_argv(*args, f'{frm}/', f'{to}/'),
        capture_output=True,
        text=True,
        env=env,
    )
    print("RSYNC DEBUG STDOUT:\n", proc.stdout)
    print("RSYNC DEBUG STDERR:\n", proc.stderr)
    if ok and proc.returncode != 0:
        test_fail(f"rsync {' '.join(args)} failed (rc={proc.returncode}):\n{proc.stderr}")
    if not ok and proc.returncode == 0:
        test_fail(f"rsync {' '.join(args)} unexpectedly succeeded")
    return proc


def stored_metadata(path):
    try:
        value = os.getxattr(path, stat_attr, follow_symlinks=False).decode('ascii')
    except OSError as e:
        if e.errno != errno.ENODATA:
            test_fail(f"could not check fake-super xattr on {name}: {e}")
        test_fail(f"missing fake-super %stat xattr on {path}: {e}")
    try:
        fields = value.split()
        mode = int(fields[0], 8) & 0o7777
        uid, gid = (int(part) for part in fields[2].split(':'))
        return mode, uid, gid
    except (ValueError, IndexError):
        test_fail(f"malformed fake-super %stat xattr on {path}: {value!r}")


def check_destination():
    for name, original_mode in modes.items():
        path = dst / name
        st = os.lstat(path)
        expected = 0o700 if stat.S_ISDIR(st.st_mode) else 0o600
        actual = stat.S_IMODE(st.st_mode)
        if actual != expected:
            test_fail(f"{name}: destination mode {actual:04o}, expected {expected:04o}")
        saved_mode, saved_uid, saved_gid = stored_metadata(path)
        if saved_mode != original_mode:
            test_fail(f"{name}: saved mode {saved_mode:04o}, expected {original_mode:04o}")
        source_stat = os.stat(src / name)
        if (saved_uid, saved_gid) != (source_stat.st_uid, source_stat.st_gid):
            test_fail(f"{name}: saved uid/gid {(saved_uid, saved_gid)} do not match "
                      f"source {(source_stat.st_uid, source_stat.st_gid)}")
        if (st.st_uid, st.st_gid) != (os.getuid(), os.getgid()):
            test_fail(f"{name}: destination ownership changed unexpectedly")


# Without fake-super on the receiving side, --chmod-dest must be rejected.
proc = run(['-a', '-M--chmod-dest=F600,D700'], src, bad, ok=False)
if '--fake-super' not in proc.stderr:
    test_fail(f"missing --fake-super diagnostic: {proc.stderr!r}")

# Put --chmod-dest before --fake-super to verify that validation happens
# after all receiver options have been parsed.
run(['-a', '--numeric-ids',
     '-M--chmod-dest=F600,D700', '-M--fake-super'], src, dst)
check_destination()

# Existing destination mode drift must be corrected even though the fake-super
# xattr still describes the unchanged source mode.
os.chmod(dst / 'plain', 0o777)
run(['-a', '--numeric-ids',
     '-M--chmod-dest=F600,D700', '-M--fake-super'], src, dst)
check_destination()

# The sender must remain untouched: fake-super metadata belongs only on dst.
for name in modes:
    try:
        os.getxattr(src / name, stat_attr, follow_symlinks=False)
    except OSError as e:
        if e.errno != errno.ENODATA:
            test_fail(f"could not check fake-super xattr on {name}: {e}")
    else:
        test_fail(f"source was modified with a fake-super xattr: {name}")

# A chmod-only source change (same contents and mtime) must update the saved
# original mode without relaxing the actual destination mode.
old_mtime = (src / 'plain').stat().st_mtime_ns
os.chmod(src / 'plain', 0o640)
os.utime(src / 'plain', ns=(old_mtime, old_mtime))
modes['plain'] = 0o640
run(['-a', '--numeric-ids',
     '-M--chmod-dest=F600,D700', '-M--fake-super'], src, dst)
check_destination()


# Re-run from the fake-super backup as sender.  This must reconstruct the
# original modes even though the on-disk backup modes are restrictive.
rsh = make_local_fake_super_rsh()
env = os.environ.copy()
env['RSYNC_RSH'] = f'{shlex.quote(str(rsh))} {shlex.quote(rsync_argv()[0])}'
run(
    ['-a', '--numeric-ids'],
    'localhost:' + str(dst) + '/',
    str(restored) + '/',
    env=env,
)
#print("restore args:", args)
print("restored setuid stat:", oct(os.stat(restored / "setuid").st_mode))
print("restored setuid xattrs:", os.listxattr(restored / "setuid"))
mode = stat.S_IMODE(os.stat(restored / 'setuid').st_mode)
if mode != 0o4755:
    fail(f'restored setuid: mode {mode:04o}, expected 4755')
if 'user.rsync.%stat' in os.listxattr(restored / 'setuid'):
    fail('restored setuid still has fake-super metadata')
for name, original_mode in modes.items():
    actual = stat.S_IMODE(os.lstat(restored / name).st_mode)
    if actual != original_mode:
        test_fail(f"restored {name}: mode {actual:04o}, expected {original_mode:04o}")
    st = os.lstat(restored / name)
    if (st.st_uid, st.st_gid) != (os.getuid(), os.getgid()):
        test_fail(f"restored {name}: ownership {(st.st_uid, st.st_gid)} "
                  f"does not match source {(os.getuid(), os.getgid())}")

print("chmod-dest-fake-super: restrictive destination modes and original mode restore ok")
