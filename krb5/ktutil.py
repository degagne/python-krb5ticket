import typing as t
import re
import io
import pandas
import pathlib
import subprocess

from krb5.errors import KtutilCommandNotFound


class ktutil:
    """
    Kerberos keytab maintenance utility.
    
    This class provides a wrapper around the ``ktutil`` command-line
    interface, which provides administrators the ability to read, write,
    or edit entries in keytab files.
    """
    def __init__(self) -> t.NoReturn:
        self.ktutil_init()

    def __del__(self):
        """
        Close ``subprocess`` object.
        """
        if self._cursor:
            self._cursor.terminate()
            self._cursor.wait(timeout=30)

    @property
    def error(self) -> str:
        """
        Gets STDERR stream output.
        
        :return: last known error message from the STDERR stream.
        """
        return self._error_msg

    @error.setter
    def error(self, stderr: io.TextIOWrapper) -> None:
        """
        Sets STDERR stream output.
        
        :param stdout: ``io.TextIOWrapper`` object of the STDERR stream.
        :return: None
        """
        self._error_msg = stderr.readline().strip()

    @property
    def keylist(self) -> dict:
        """
        Gets the current keylist of the loaded Kerberos keytab file.
        
        :return: dictionary object containing the current keylist.
        """
        return self._keylist if hasattr(self, "_keylist") else None

    @keylist.setter
    def keylist(self, stdout: io.TextIOWrapper) -> t.List[dict]:
        """
        Sets the current keylist of the loaded Kerberos keytab file.
        
        :param stdout: ``io.TextIOWrapper`` object of the STDOUT stream.
        :return: None
        """
        self._keylist = []
        raw_keys = []
        for line in stdout.readlines():
            if (not re.findall(".*ktutil:.*", line) and 
                not line.startswith("-")):
                raw_keys.append(line)

        if len(raw_keys) != 0:
            keystrings = io.StringIO("\n".join(raw_keys))
            data = pandas.read_csv(
                keystrings, sep="\s+").to_dict(orient="index")
            if 0 in data:
                for keylist in data.values():
                    keydata = {}
                    for k, v in keylist.items():
                        keydata[k.lower()] = v
                    self._keylist.append(keydata)

    @staticmethod
    def resolve_command(command: str):
        """
        Identifies the command location of the ``ktutil`` executable.
        
        :param command: command name.
        :return: path to command executable.
        :raises: ``KtutilCommandNotFound`` if the command executable was not
            found within the path environment variable.
        """
        try:
            path = subprocess.check_output(
                ["which", command], stderr=subprocess.DEVNULL).strip()
            return path.decode("UTF-8")
        except subprocess.CalledProcessError:
            raise KtutilCommandNotFound("Cannot find 'ktutil' command.")

    @staticmethod
    def resolve_keytab_file(keytab_file: str) -> str:
        """
        Resolves Kerberos keytab file from the home directory
        location.

        :param keytab_file: Kerberos V5 keytab file.
        :return: resolved keytab file with path.
        """
        home_dir = pathlib.Path.home()
        keytab_file = home_dir.joinpath(keytab_file)
        return str(keytab_file)

    @staticmethod
    def keytab_exists(keytab_file: str) -> t.Union[str, bool]:
        """
        Verifies if a Kerberos key table file exists.
        
        :param keytab_file: Kerberos key table file.
        :return: resolved path for the Kerberos keytab file if exists, 
            otherwise False.
        """
        keytab_file = ktutil.resolve_keytab_file(keytab_file)
        return keytab_file \
            if pathlib.Path(keytab_file).exists() else False

    @staticmethod
    def validate_entry_type(type: str) -> str:
        """
        Verifies the entry type used for adding entry.

        :param type: Kerberos keytab entry type (password or key).
        :return: validated keytab entry type.
        """
        return "password" if type not in ["password", "key"] else type

    def ktutil_init(self) -> None:
        """
        Instantiates the ``ktutil`` command-line interface.
        """
        self._cursor = subprocess.Popen(
            ktutil.resolve_command("ktutil"), stdin=subprocess.PIPE, 
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
            universal_newlines=True, close_fds=True)

    def list(self) -> "ktutil":
        """
        Displays the current keylist.
        
        :return: ``ktutil`` object.
        """
        self._cursor.stdin.write("list\n")
        self._cursor.stdin.flush()
        return self

    def read_kt(self, keytab_file: str) -> "ktutil":
        """
        Reads the Kerberos V5 keytab file keytab into the current
        keylist.

        :param keytab_file: Kerberos V5 keytab file.
        :return: ``ktutil`` object.
        """
        keytab_file = ktutil.resolve_keytab_file(keytab_file)
        self._cursor.stdin.write(f"read_kt {keytab_file}\n")
        self._cursor.stdin.flush()
        return self

    def write_kt(self, keytab_file: str) -> "ktutil":
        """
        Writes the current keylist to a keytab file.

        :param keytab_file: Kerberos V5 keytab file.
        :return: ``ktutil`` object.
        """
        keytab_file = ktutil.resolve_keytab_file(keytab_file)
        self._cursor.stdin.write(f"write_kt {keytab_file}\n")
        self._cursor.stdin.flush()
        return self

    def delete_entry(self, slot: int) -> "ktutil":
        """
        Deletes the entry in slot number from the current keylist.

        :param slot: keylist slot number.
        :return: ``ktutil`` object.
        """
        self._cursor.stdin.write(f"delete_entry {slot}\n")
        self._cursor.stdin.flush()
        return self

    def add_entry(
        self,
        principal: str,
        password_or_key: str,
        kvno: int,
        enctype: str,
        type: t.Optional[str] = "password"
    ) -> "ktutil":
        """
        Adds principal to keylist using key or password.
        
        :param principal:
        :param password_or_key:
        :param kvno:
        :param enctype:
        :param type:
        :return: ``ktutil`` object.
        """
        type = ktutil.validate_entry_type(type)
        self._cursor.stdin.write(
            f"addent -{type} -p {principal} -k {kvno} -e {enctype}\n")
        self._cursor.stdin.write(f"{password_or_key}\n")
        self._cursor.stdin.flush()
        return self

    def quit(self) -> None:
        """
        Quits ktutil.

        :return: None
        """
        self._cursor.stdin.write("quit\n")
        self._cursor.stdin.flush()
        self.keylist = self._cursor.stdout
        self.returncode = self._cursor.poll()
        self.error = self._cursor.stderr

        # Close pipes
        self._cursor.stdin.close()
        self._cursor.stdout.close()
        self._cursor.stderr.close()