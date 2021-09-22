import typing as t
import shutil

from krb5 import ktutil


def create_entries(
    principal: str,
    keytab_file: str,
    password_or_passphrase: str,
    enctypes: t.List[str],
    kvno: t.Optional[int] = 1,
    entry_type: t.Optional[str] = "password"):
    """
    Creates one or more entries and write keylist to a Kerberos keytab.
    
    :param principal: Kerberos principal.
    :param keytab_file: Kerberos V5 keytab file name. The file can be a 
        relative path read from the user's home directory.
    :param password_or_passphrase: password or passphrase for key.
    :param enctypes: list of encryption types to add.
    :param kvno: key version number.
    :param entry_type: keylist entry type -- either "password" or "key".
    """
    keytab_file = ktutil.resolve_keytab_file(keytab_file)
    kt = ktutil()
    for enctype in enctypes:
        kt.add_entry(
            principal, password_or_passphrase, kvno, enctype, entry_type)
    kt.write_kt(keytab_file)
    kt.quit()

    return True if kt.error else False


def list_entries(keytab_file: str) -> t.Union[t.List[dict], bool]:
    """
    Returns the current keylist for a Kerberos keytab file.
    
    :param keytab_file: Kerberos V5 keytab file name. The file can be a 
        relative path read from the user's home directory.
    :return: List of dictionary items containing the keylist information, 
        otherwise False.
    """
    keytab_file = ktutil.keytab_exists(keytab_file)
    if keytab_file:
        kt = ktutil()
        kt.read_kt(keytab_file)
        kt.list()
        kt.quit()
        return kt.keylist
    return False


def delete_entries(keytab_file: str, slots: t.List[int]) -> bool:
    """
    Deletes one or more entries from a Kerberos keytab.
    
    This function will only delete slots that exist within the keylist. 
    Once the slots are deleted, the current keylist will be written to 
    a temporary file. This avoids having the keylist appended to the
    keylist within the keytab file. Once the keylist is written to the 
    temporary file, the temporary file will be move/renamed the original
    keytab filename.
    
    :param keytab_file: Kerberos V5 keytab file name. The file can be a 
        relative path read from the user's home directory.
    :param slots: list of slots to be deleted from the keylist.
    :return: True on success, otherwise False.
    """
    keytab_file = ktutil.keytab_exists(keytab_file)
    if not keytab_file or not isinstance(slots, list):
        return False

    keytab_tmp = ktutil.resolve_keytab_file(f"{keytab_file}.tmp")

    kt = ktutil()

    # Read the Kerberos keytab file first to check if slots exist before 
    # trying to delete them.
    kt.read_kt(keytab_file)
    kt.list()
    kt.quit()
    existing_slots = [
        key["slot"] for key in kt.keylist if key["slot"] in slots]

    if len(existing_slots) == 0:
        return False # No slots exist to be deleted.

    # Re-initialize 'ktutil' command and delete the slot(s).
    # Write the current keylist to a temporary file, then rename
    # the temporary file to the original name. This avoids the
    # duplication caused by the ``write_kt`` invocation.

    kt.ktutil_init()
    kt.read_kt(keytab_file)
    for slot in existing_slots:
        kt.delete_entry(slot)
    kt.write_kt(keytab_tmp)
    kt.quit()

    shutil.move(keytab_tmp, keytab_file)

    return True if kt.error else False
