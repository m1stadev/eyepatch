from importlib.metadata import version

from .aarch64 import Patcher as AArch64Patcher  # noqa: F401
from .arm import Patcher as ARMPatcher  # noqa: F401

__version__ = version(__package__)
