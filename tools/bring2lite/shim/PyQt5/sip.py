# Inert PyQt5.sip shim — any attribute resolves to a no-op stub.
from ._stub import __getattr__  # noqa: F401  (PEP 562 module-level __getattr__)
