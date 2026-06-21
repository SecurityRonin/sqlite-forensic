# Inert PyQt5.QtWidgets shim — any imported name resolves to a no-op stub class.
from ._stub import __getattr__  # noqa: F401  (PEP 562 module-level __getattr__)
