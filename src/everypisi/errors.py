class EveryPisiError(Exception):
    """Expected user-facing EveryPisi failure."""


class UnsupportedFormatError(EveryPisiError):
    pass


class UnsafeArchiveError(EveryPisiError):
    pass


class ConversionRefused(EveryPisiError):
    pass


class ResourceLimitError(EveryPisiError):
    """Input or expanded archive exceeds a safety resource limit."""
