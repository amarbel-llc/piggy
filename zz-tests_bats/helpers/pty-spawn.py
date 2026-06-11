#!/usr/bin/env python3
"""Allocate a real PTY, run argv under it, exit with the child's code.

Drop-in replacement for the inline one-liner

    python3 -c 'import os, pty, sys; sys.exit(os.waitstatus_to_exitcode(pty.spawn(sys.argv[1:])))'

used by the SSH_ASKPASS_REQUIRE tty tests in
conformance/piggy_askpass.bats. Those tests need a *real* terminal to
exercise contrib/piggy-askpass.sh's /dev/tty read branch, so the PTY
cannot be mocked away.

Why this exists instead of `pty.spawn` — surface the REAL errno:

  stdlib pty.py's openpty() wraps os.openpty() in a try/except that, on
  ANY OSError, silently falls through to a legacy /dev/ptyXX scan and —
  finding no such device nodes on modern macOS/Linux — re-raises a
  misleading `OSError: out of pty devices`. So a sandbox EPERM on
  /dev/ptmx (which is what actually happens under the batman conformance
  sandbox) gets laundered into a phantom "pool exhausted" message that
  sent a debugging session down four wrong hypotheses (race, fd limit,
  parallelism, leak) before the true cause — EPERM — was found. See
  piggy#167.

  This helper calls os.openpty() directly and lets its OSError propagate
  uncaught, and on failure dumps ground truth (real errno/strerror, a
  direct /dev/ptmx open probe, the live /dev/ttys* count) to stderr so
  the test diagnostic names the actual kernel verdict instead of the
  masked one. It also serializes allocation under an fcntl.flock and
  releases the master fd as soon as the child's output EOFs — both
  cheap, correct hygiene, though neither is the fix for the EPERM case.

Usage: pty-spawn.py <argv0> [args...]   (parent stdin is piped to the
PTY, PTY output is copied to parent stdout, exactly like pty.spawn).
"""

import errno
import fcntl
import os
import select
import sys
import tempfile

# Lockfile shared across all concurrent invocations. Prefer the bats
# per-run tmpdir so it's cleaned with the run; fall back to a fixed
# name under the system tmpdir. The lock only needs a stable path —
# its contents are irrelevant.
_lock_dir = os.environ.get("BATS_RUN_TMPDIR") or tempfile.gettempdir()
_LOCK_PATH = os.path.join(_lock_dir, "piggy-pty-spawn.lock")


def _dump_pty_ground_truth(masked_err):
    """Print the REAL openpty failure to stderr at the moment it happens.

    We call os.openpty() directly (see _spawn), so its OSError already
    carries the true errno — but stdlib pty.py would have masked the same
    failure as "out of pty devices" via its legacy /dev/ptyXX fallback.
    This probe records ground truth at the failing call site so the
    diagnostic is unambiguous:
      - the real errno/strerror from os.openpty() called directly
      - whether /dev/ptmx itself can be opened (and its errno if not)
      - the live /dev/ttys* slave count at failure time
    so the test diagnostic carries the actual kernel verdict instead of
    the masked message. Diagnostic only — never raises.
    """
    w = sys.stderr.write
    w("\n[pty-spawn ground truth] os.openpty() raised: "
      f"{masked_err!r} (errno={masked_err.errno})\n")
    # Direct os.openpty() — the modern /dev/ptmx path, no BSD fallback.
    try:
        m, s = os.openpty()
        os.close(m)
        os.close(s)
        w("[pty-spawn ground truth] os.openpty() direct: OK "
          "(so the failure is inside pty.fork's fork/setsid, not openpty)\n")
    except OSError as e:
        w("[pty-spawn ground truth] os.openpty() direct: FAILED "
          f"errno={e.errno} ({os.strerror(e.errno)})\n")
    # Can we even open the ptmx multiplexer directly?
    try:
        fd = os.open("/dev/ptmx", os.O_RDWR)
        os.close(fd)
        w("[pty-spawn ground truth] open(/dev/ptmx): OK\n")
    except OSError as e:
        w("[pty-spawn ground truth] open(/dev/ptmx): FAILED "
          f"errno={e.errno} ({os.strerror(e.errno)})\n")
    # Live slave count — the number debug-pty-holders reports.
    try:
        import glob
        w("[pty-spawn ground truth] live /dev/ttys* count: "
          f"{len(glob.glob('/dev/ttys*'))}\n")
    except OSError:
        pass


def _spawn(argv):
    """Fork a child attached to a fresh PTY slave; pump I/O; return wait status.

    Allocates the PTY pair with os.openpty() DIRECTLY rather than via
    pty.fork(). This is deliberate and load-bearing: stdlib pty.py wraps
    os.openpty() in a try/except that, on ANY OSError, silently falls
    through to a legacy /dev/ptyXX scan and — finding no such nodes on
    modern systems — re-raises the misleading "out of pty devices". That
    masking turned a sandbox EPERM on /dev/ptmx into a phantom
    "pool exhausted" error (see piggy#167). By calling os.openpty()
    ourselves, its real OSError (errno + strerror) propagates uncaught,
    so the test diagnostic names the actual kernel verdict.

    The flock around allocation serializes concurrent allocations; it is
    not what fixes piggy#167 (an EPERM denial, not a race) but is cheap
    and correct defense if real pool contention ever applies.
    """
    lock_fd = os.open(_LOCK_PATH, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        # os.openpty() — the modern /dev/ptmx path. Its OSError carries
        # the true errno and is NOT swallowed here, unlike pty.fork()'s.
        try:
            master_fd, slave_fd = os.openpty()
        except OSError as e:
            _dump_pty_ground_truth(e)
            raise
        pid = os.fork()
        if pid == 0:
            # Child: become session leader, adopt the slave as controlling
            # tty on stdin/stdout/stderr (what pty.fork() does internally),
            # then exec the target. On failure exit 127 like a shell
            # "command not found" rather than dumping a traceback onto the
            # PTY (which the parent would echo into test output).
            try:
                os.close(master_fd)
                os.setsid()
                for target_fd in (0, 1, 2):
                    os.dup2(slave_fd, target_fd)
                if slave_fd > 2:
                    os.close(slave_fd)
                os.execvp(argv[0], argv)
            except OSError:
                os._exit(127)
        # Parent: the slave lives in the child now; close our copy and
        # release the lock — the scarce allocation is done.
        os.close(slave_fd)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)

    _pump(master_fd)
    # Master closed inside _pump as soon as output EOFs; now reap.
    _, status = os.waitpid(pid, 0)
    return status


def _pump(master_fd):
    """Copy parent stdin -> PTY master and PTY master -> parent stdout.

    Returns (closing the master fd) when the master reaches EOF, i.e.
    the child has exited and the slave is gone. Closing here — not at
    interpreter teardown — is what returns the PTY to the pool ASAP.
    """
    stdin_fd = sys.stdin.fileno()
    stdout_fd = sys.stdout.fileno()
    fds = [master_fd, stdin_fd]
    try:
        while fds:
            try:
                readable, _, _ = select.select(fds, [], [])
            except OSError as e:
                if e.errno == errno.EINTR:
                    continue
                raise
            if master_fd in readable:
                try:
                    data = os.read(master_fd, 1024)
                except OSError:
                    data = b""  # master gone (child exited) -> EOF
                if not data:
                    break  # child output EOF; we're done
                os.write(stdout_fd, data)
            if stdin_fd in readable:
                data = os.read(stdin_fd, 1024)
                if not data:
                    # Parent stdin EOF: stop forwarding it, but keep
                    # draining the master until the child exits.
                    fds.remove(stdin_fd)
                else:
                    try:
                        os.write(master_fd, data)
                    except OSError:
                        fds.remove(stdin_fd)
    finally:
        os.close(master_fd)


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("pty-spawn.py: missing command to run\n")
        return 2
    status = _spawn(sys.argv[1:])
    return os.waitstatus_to_exitcode(status)


if __name__ == "__main__":
    sys.exit(main())
