"""Process lifecycle of the gateway: how it stops."""
import os
import signal
import time
import unittest

from mcp_governance_gateway.server import ShutdownRequested, install_shutdown_signal


class ShutdownSignalTests(unittest.TestCase):
    def test_sigterm_unwinds_the_main_thread_like_an_interrupt(self):
        # A container runtime stops the gateway with SIGTERM. The default
        # disposition kills the process mid-request; the handler instead raises
        # into the main thread, which is where `serve_forever` runs, so `main`
        # reaches the same `finally` an interrupt does.
        previous = signal.getsignal(signal.SIGTERM)
        self.addCleanup(signal.signal, signal.SIGTERM, previous)
        install_shutdown_signal()
        with self.assertRaises(ShutdownRequested):
            os.kill(os.getpid(), signal.SIGTERM)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:   # the handler runs at a bytecode boundary
                pass


if __name__ == "__main__":
    unittest.main()
