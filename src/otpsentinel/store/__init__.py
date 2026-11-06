from .base import Store, StoreError
from .memory import MemoryStore

__all__ = ["Store", "StoreError", "MemoryStore", "RedisStore"]


def __getattr__(name):
    if name == "RedisStore":
        from .redis_store import RedisStore
        return RedisStore
    raise AttributeError(name)
