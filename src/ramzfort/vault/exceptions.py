class ConcurrentModificationError(RuntimeError):
    pass


class InvalidMasterPasswordError(ValueError):
    pass


class InvalidRecoveryKeyError(ValueError):
    pass


class RecoveryError(RuntimeError):
    pass


class VaultCorruptedError(ValueError):
    pass