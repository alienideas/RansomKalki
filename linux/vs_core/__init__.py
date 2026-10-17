"""VectorStryke core — modular, OOP foundation for EDR/XDR growth."""
__version__ = "1.7.0"

from .paths import Paths
from .config import ConfigManager
from .engine import Engine

__all__ = ["Paths", "ConfigManager", "Engine", "__version__"]
