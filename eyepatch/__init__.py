from importlib.metadata import version

from loguru import logger as _logger

from .aarch64 import Patcher as AArch64Patcher  # noqa: F401
from .arm import Patcher as ARMPatcher  # noqa: F401
from .errors import *  # noqa: F403

__version__ = version(__package__)

_logger.disable('eyepatch')
