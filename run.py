import ops_web.ops_web
import signal
import sys


def handle_sigterm(_signal, _frame):
    sys.exit()


signal.signal(signal.SIGTERM, handle_sigterm)
ops_web.ops_web.main()
