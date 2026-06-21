# Inert headless PyQt5 shim for bring2lite CLI mode.
#
# bring2lite's classes/visualizer.py does `from PyQt5.QtWidgets import ...` and
# `from PyQt5 import sip` at module load, but the Visualizer is only used in
# `--gui 1` mode. In the head-to-head we always run `--gui 0`, so no Qt symbol is
# ever called. This shim lets the import succeed on a host without PyQt5.
#
# scripts/run-bring2lite.sh prepends this shim to PYTHONPATH ONLY when a real
# PyQt5 is absent (a genuine install always wins).

from . import sip  # noqa: F401  (make `from PyQt5 import sip` resolvable)
