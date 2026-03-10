# auto-import modules in this package so adapter classes register themselves
import importlib, pkgutil  # pragma: no cover
for _finder, name, _ispkg in pkgutil.iter_modules(__path__):  # pragma: no cover
    importlib.import_module(f"{__name__}.{name}")
