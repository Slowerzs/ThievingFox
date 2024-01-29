from impacket.smbconnection import SMBConnection, SessionError
from impacket import smb, smb3
from impacket.smb3structs import (
    FILE_RENAME_INFORMATION_TYPE_2,
    FILE_READ_EA,
    DELETE,
    SYNCHRONIZE,
    FILE_SHARE_READ,
    FILE_SHARE_DELETE,
    FILE_SHARE_WRITE,
    FILE_OPEN,
    SMB2_0_INFO_FILE,
    SMB2_FILE_RENAME_INFO,
    SMB2_OPLOCK_LEVEL_LEASE,
)
import ntpath
from impacket import uuid


def renameLockedFiled(
    smbConnection: SMBConnection, shareName: str, oldPath: str, newPath: str
) -> bool:
    try:
        return rename(smbConnection._SMBConnection, shareName, oldPath, newPath)
    except (smb.SessionError, smb3.SessionError) as e:
        raise SessionError(e.get_error_code(), e.get_error_packet())


def rename(
    smbConnection: smb.SMB | smb3.SMB3, shareName: str, oldPath: str, newPath: str
):
    oldPath = oldPath.replace("/", "\\")
    oldPath = ntpath.normpath(oldPath)
    if len(oldPath) > 0 and oldPath[0] == "\\":
        oldPath = oldPath[1:]

    newPath = newPath.replace("/", "\\")
    newPath = ntpath.normpath(newPath)
    if len(newPath) > 0 and newPath[0] == "\\":
        newPath = newPath[1:]

    treeId = smbConnection.connectTree(shareName)
    fileId = None

    try:
        fileId = smbConnection.create(
            treeId,
            oldPath,
            FILE_READ_EA | DELETE | SYNCHRONIZE,  # This cannot be MAXIMUM_ALLOWED
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            0x200020,
            FILE_OPEN,
            0,
            oplockLevel=SMB2_OPLOCK_LEVEL_LEASE,
            createContexts=[],
        )
        renameReq = FILE_RENAME_INFORMATION_TYPE_2()
        renameReq["ReplaceIfExists"] = 1
        renameReq["RootDirectory"] = "\x00" * 8
        renameReq["FileNameLength"] = len(newPath) * 2
        renameReq["FileName"] = newPath.encode("utf-16le")
        smbConnection.setInfo(
            treeId,
            fileId,
            renameReq,
            infoType=SMB2_0_INFO_FILE,
            fileInfoClass=SMB2_FILE_RENAME_INFO,
        )
    finally:
        if fileId is not None:
            smbConnection.close(treeId, fileId)
        smbConnection.disconnectTree(treeId)

    return True
