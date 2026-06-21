# Shared stub machinery for the inert PyQt5 shim.
#
# Any attribute access yields a callable, subclassable no-op class. This lets
# `from PyQt5.QtWidgets import <anything>` succeed for an arbitrary symbol list
# without enumerating Qt's API, while never providing real behaviour (none is
# needed: visualizer.py is not exercised in bring2lite's --gui 0 CLI path).


class _Stub:
    def __init__(self, *args, **kwargs):
        pass

    def __call__(self, *args, **kwargs):
        return _Stub()

    def __getattr__(self, name):
        return _Stub()


def __getattr__(name):  # module-level: PEP 562
    # Return a fresh stub class for any requested name (QMainWindow, sip, ...).
    return type(name, (_Stub,), {})
