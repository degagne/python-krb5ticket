import gssapi
import typing as t
import datetime as dt
import pathlib
import shutil
import tempfile

from krb5 import KeytabFileNotExists


class Krb5:
    """
    Kerberos V5 protocol.
    
    This class provides the functionality to aquire Kerberos ticket-granting
    tickets (TGTs) using either a key table file or password.
    
    .. important::
    
        **SECURITY ADVISORY**
        
        From a security perspective, the ``acquire_with_password`` 
        method should not be  used in a Production environment as it 
        passes a plain text password. To initialize credentials, 
        please use ``acquire_with_keytab``.

    :param principal: Kerberos principal.
    :param ccache: Kerberos credential cache.
    """
    def __init__(self, principal: str, ccache: str = None) -> t.NoReturn:
        self._store = {}
        self.principal = principal
        self.ccache = ccache

    @property
    def principal(self) -> gssapi.Name:
        """
        Gets the Kerberos principal.
        """
        return self._principal

    @principal.setter
    def principal(self, principal: str) -> None:
        """
        Sets the Kerberos principal.
        """
        self._principal = gssapi.Name(
            principal, gssapi.NameType.kerberos_principal)

    @property
    def ccache(self) -> t.Union[None, dict]:
        """
        Gets Kerberos credential cache.
        """
        return self._ccache

    @ccache.setter
    def ccache(self, ccache: str):
        """
        Sets Kerberos credential cache.
        """
        self._ccache = {"ccache": ccache} if ccache else None

    @property
    def keytab(self) -> str:
        """
        Gets the Kerberos key table file.
        """
        return getattr(self, "_keytab", None)

    @keytab.setter
    def keytab(self, keytab: str) -> None:
        """
        Sets the Kerberos key table file.
        """
        keytab = pathlib.Path(keytab).resolve()
        if not keytab.exists():
            raise KeytabFileNotExists(
                f"Kerberos keytab file '{keytab}' doesn't exist.")
        self._keytab = str(keytab)

    @property
    def store(self) -> t.Union[None, dict]:
        """
        Gets the Kerberos credential store.
        """
        if self.keytab:
            self._store.update(client_keytab=self.keytab)
        if self.ccache:
            self._store.update(self.ccache)
        return self._store

    @property
    def lifetime(self) -> str:
        """
        Gets the Kerberos credential expiry date.
        """
        return getattr(self, "_lifetime", None)

    @lifetime.setter
    def lifetime(self, seconds: int) -> None:
        """
        Sets the Kerberos credential expiry date.
        """
        if isinstance(seconds, int):
            timestamp = dt.datetime.now() + dt.timedelta(0, seconds)
            self._lifetime = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        else:
            self._lifetime = None

    @property
    def is_expired(self) -> str:
        """
        Gets the Kerberos credential expiry state.
        """
        return getattr(self, "_is_expired", None)

    @is_expired.setter
    def is_expired(self, is_expired: bool) -> None:
        """
        Sets the Kerberos credential expiry state.
        """
        self._is_expired = is_expired

    def _store_creds(
        self,
        creds: gssapi.Credentials,
        store: t.Union[None, dict],
        usage: str = "initiate", 
        set_default: bool = True,
        overwrite: bool = True
    ) -> bool:
        """
        Stores Kerberos credentials in cache.
        
        :param creds: ``gssapi.Credentials`` object.
        :param usage: usage to store the credentials with -- either 
            'both', 'initiate' or 'accept'.
        :param set_default: whether or not to set these credentials 
            as the default for the given store.
        :param overwrite: whether or not to overwrite existing 
            credentials stored with the same name.
        :return: True when credentials are successfully stored, 
            otherwise False.
        """
        try:
            creds.store(store=store, usage=usage, set_default=set_default,
                        overwrite=overwrite)
            return True
        except (
            gssapi.exceptions.GSSError,
            gssapi.exceptions.ExpiredCredentialsError,
            gssapi.exceptions.OperationUnavailableError,
            gssapi.exceptions.DuplicateCredentialsElementError,
        ):
            return False

    def _acquire_creds(
        self,
        raw_creds: t.Union[dict, gssapi.raw.creds.Creds]
    ) -> t.Union[None, bool, gssapi.Credentials]:
        """
        Acquire Kerberos credentials.

        :param raw_creds: ``gssapi.raw.creds.Creds`` object.
        :return: ``gssapi.Credentials`` object on success, None 
            when the credential cache is expired, and False on 
            errors.
        """
        try:
            if isinstance(raw_creds, gssapi.raw.creds.Creds):
                creds = gssapi.Credentials(raw_creds)
            else:
                creds = gssapi.Credentials(**raw_creds)
            creds.inquire()
            self.lifetime = creds.lifetime
            self.is_expired = False
            return creds
        except gssapi.exceptions.ExpiredCredentialsError:
            self._lifetime = None
            self.is_expired = True
            return None
        except (
            gssapi.exceptions.GSSError,
            gssapi.exceptions.MissingCredentialsError,
            gssapi.exceptions.InvalidCredentialsError
        ):
            return False

    def acquire_with_keytab(
        self,
        keytab: str,
        usage: str = "initiate",
        set_default: bool = True,
        overwrite: bool = True
    ) -> bool:
        """
        Acquire Kerberos ticket-granting ticket (TGT) with keytab.
        
        :param keytab: Kerberos keytab file.
        :param usage: usage to store the credentials with -- either 'both',
            'initiate' or 'accept'.
        :param set_default: whether or not to set these credentials as the
            default for the given store.
        :param overwrite: whether or not to overwrite existing credentials
            stored with the same name.
        :return: True on success, otherwise False.
        """
        self.keytab = keytab
        krb5_creds = {
            "name": self.principal,
            "usage": usage,
            "store": self.store
        }
        creds = self._acquire_creds(krb5_creds)
        if creds:
            return True

        temp_dir = tempfile.mkdtemp("-krb5")
        temp_ccache = pathlib.Path(temp_dir).joinpath("ccache")
        try:
            krb5_creds.setdefault("store", {})["ccache"] = temp_ccache
            return self._store_creds(
                self._acquire_creds(krb5_creds),
                self.ccache,
                usage,
                set_default,
                overwrite)
        finally:
            shutil.rmtree(str(temp_dir), ignore_errors=True)

    def acquire_with_password(
        self,
        password: str,
        usage: str = "initiate",
        set_default: bool = True,
        overwrite: bool = True
    ) -> bool:
        """
        Acquire Kerberos ticket-granting ticket (TGT) with password.
        
        :param password: Kerberos credential password.
        :param usage: usage to store the credentials with -- either 
            'both', 'initiate' or 'accept'.
        :param set_default: whether or not to set these credentials 
            as the default for the given store.
        :param overwrite: whether or not to overwrite existing 
            credentials stored with the same name.
        :return: True on success, otherwise False.
        """
        try:
            krb5_creds = gssapi.raw.acquire_cred_with_password(
                name=self.principal, 
                password=password.encode("UTF-8"),
                usage=usage,
                mechs=gssapi.raw.MechType.kerberos
            )
        except gssapi.exceptions.GSSError:
            # Unable to acquire Kerberos credentials to obtain a
            # ticket-granting ticket (TGT).
            return False

        return self._store_creds(
            self._acquire_creds(krb5_creds.creds),
            self.store,
            usage,
            set_default,
            overwrite)
