"""Private probe watchdog: own handlers in this process, never in the Rust test harness."""
import os
import signal
import subprocess
import sys
import threading
import time


def main():
    cancelled = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: cancelled.set())
    # The sole write handle belongs to the Rust test. EOF also covers abrupt parent death.
    def parent_closed():
        os.read(sys.stdin.fileno(), 1)
        cancelled.set()
    threading.Thread(target=parent_closed, daemon=True).start()
    deadline = time.monotonic() + float(sys.argv[1])
    child = subprocess.Popen(sys.argv[2:], stdin=subprocess.DEVNULL,
                             start_new_session=(os.name == 'posix'))
    try:
        while True:
            if cancelled.is_set() or time.monotonic() >= deadline:
                return 130 if cancelled.is_set() else 124
            status = child.poll()
            if status is not None:
                return status if status >= 0 else 128 - status
            cancelled.wait(0.05)
    finally:
        if child.poll() is None:
            # Keep the group leader unreaped until its whole group has been signalled.
            if os.name == 'posix':
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                subprocess.run(['taskkill', '/F', '/T', '/PID', str(child.pid)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=5, check=True)
            child.wait(timeout=5)


if __name__ == '__main__':
    sys.exit(main())
