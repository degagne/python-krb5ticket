class KeytabFileNotExists(RuntimeError):
    """
    Raised when a Kerberos keytab file doesn't exist.
    """
    pass


class KtutilCommandNotFound(RuntimeError):
    """
    Raised when ``ktutil`` command-line interface not found.
    """
    pass
