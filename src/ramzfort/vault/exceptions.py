class ConcurrentModificationError(RuntimeError):
    pass


class InvalidMasterPasswordError(ValueError):
    pass


class VaultCorruptedError(ValueError):
    pass