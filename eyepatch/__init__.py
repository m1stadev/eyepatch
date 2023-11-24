from importlib.metadata import version

from .patcher import Patcher  # noqa: F401

__version__ = version(__package__)
