from impacket.dcerpc.v5 import transport, rrp, scmr
from impacket.dcerpc.v5.dtypes import READ_CONTROL
from impacket.smbconnection import SMBConnection
from struct import unpack
from time import sleep
import logging


class RemoteRegistry:
    def __init__(self, smbConnection: SMBConnection) -> None:
        self.smbConnection = smbConnection
        self.remoteRegistryConnection = None

    def startRemoteRegistryService(self) -> None:
        rpc = transport.DCERPCTransportFactory("ncacn_np:445[\\pipe\\svcctl]")
        rpc.set_smb_connection(self.smbConnection)
        scmrConnection = rpc.get_dce_rpc()
        scmrConnection.connect()
        scmrConnection.bind(scmr.MSRPC_UUID_SCMR)

        response = scmr.hROpenSCManagerW(scmrConnection)
        serviceManagerHandle = response["lpScHandle"]

        response = scmr.hROpenServiceW(
            scmrConnection, serviceManagerHandle, "RemoteRegistry"
        )
        registryServiceHandle = response["lpServiceHandle"]

        response = scmr.hRQueryServiceStatus(scmrConnection, registryServiceHandle)
        registryServiceStatus = response["lpServiceStatus"]["dwCurrentState"]

        if registryServiceStatus == scmr.SERVICE_RUNNING:
            logging.info(f"Remote Registry is already started.")
            return

        elif registryServiceStatus == scmr.SERVICE_STOPPED:
            # Remote Registry service is disabled on workstation, enable if needed before starting it.
            response = scmr.hRQueryServiceConfigW(scmrConnection, registryServiceHandle)
            registryStartType = response["lpServiceConfig"]["dwStartType"]

            if registryStartType == 0x4:
                # It is disabled, let's enable it
                scmr.hRChangeServiceConfigW(
                    scmrConnection, registryServiceHandle, dwStartType=0x3
                )

            scmr.hRStartServiceW(scmrConnection, registryServiceHandle)

        return

    def connectToRemoteRegistry(self) -> None:
        rpc = transport.DCERPCTransportFactory("ncacn_np:445[\\pipe\\winreg]")
        rpc.set_smb_connection(self.smbConnection)

        self.remoteRegistryConnection = rpc.get_dce_rpc()
        # Wait for remote registry to start
        sleep(0.75)
        self.remoteRegistryConnection.connect()
        self.remoteRegistryConnection.bind(rrp.MSRPC_UUID_RRP)

        return

    def listSubKeys(self, path: str) -> list[str]:
        # First, let's get the root key that is queried.
        try:
            rootKey, subKeys = path.split("\\", 1)
        except ValueError as e:
            raise e

        # Now let's open the corresponding registry hive
        if rootKey.upper() == "HKLM":
            response = rrp.hOpenLocalMachine(self.remoteRegistryConnection)
        elif rootKey.upper() == "HKU":
            response = rrp.hOpenUsers(self.remoteRegistryConnection)
        elif rootKey.upper() == "HKCR":
            response = rrp.hOpenClassesRoot(self.remoteRegistryConnection)
        else:
            logging.error("Invalid root key")
            return

        rootKeyHandle = response["phKey"]

        response = rrp.hBaseRegOpenKey(
            self.remoteRegistryConnection,
            rootKeyHandle,
            subKeys,
            samDesired=rrp.MAXIMUM_ALLOWED
            | rrp.KEY_ENUMERATE_SUB_KEYS
            | rrp.KEY_QUERY_VALUE,
        )

        # Let's iterate over the subkeys until we get an error

        output: list[str] = []

        i = 0
        while True:
            try:
                key = rrp.hBaseRegEnumKey(
                    self.remoteRegistryConnection, response["phkResult"], i
                )
                output.append(key["lpNameOut"][:-1])
                i += 1
            except rrp.DCERPCSessionError as e:
                break

        # Close the root hive handle

        rrp.hBaseRegCloseKey(self.remoteRegistryConnection, rootKeyHandle)

        return output

    def createKey(self, path: str) -> None:
        try:
            rootKey, subKeys = path.split("\\", 1)
        except ValueError as e:
            raise e

        # Now let's open the corresponding registry hive
        if rootKey.upper() == "HKLM":
            response = rrp.hOpenLocalMachine(self.remoteRegistryConnection)
        elif rootKey.upper() == "HKU":
            response = rrp.hOpenUsers(self.remoteRegistryConnection)
        elif rootKey.upper() == "HKCR":
            response = rrp.hOpenClassesRoot(self.remoteRegistryConnection)
        elif rootKey.upper() == "HKCU":
            response = rrp.hOpenCurrentUser(self.remoteRegistryConnection)
        else:
            logging.error("Invalid root key")
            return

        rootKeyHandle = response["phKey"]

        response = rrp.hBaseRegCreateKey(
            self.remoteRegistryConnection,
            rootKeyHandle,
            subKeys,
            samDesired=READ_CONTROL | rrp.KEY_SET_VALUE | rrp.KEY_CREATE_SUB_KEY,
        )

        if response["ErrorCode"] != 0:
            logging.error(f"Failed creating registry key {path}")

        return

    def setKeyValueSZData(
        self, path: str, valueName: str, type: int, data: str
    ) -> None:
        if valueName == "(Default)":
            valueName = ""

        try:
            rootKey, subKeys = path.split("\\", 1)
        except ValueError as e:
            raise e

        # Now let's open the corresponding registry hive
        if rootKey.upper() == "HKLM":
            response = rrp.hOpenLocalMachine(self.remoteRegistryConnection)
        elif rootKey.upper() == "HKU":
            response = rrp.hOpenUsers(self.remoteRegistryConnection)
        elif rootKey.upper() == "HKCR":
            response = rrp.hOpenClassesRoot(self.remoteRegistryConnection)
        elif rootKey.upper() == "HKCU":
            response = rrp.hOpenCurrentUser(self.remoteRegistryConnection)
        else:
            logging.error("Invalid root key")
            return

        rootKeyHandle = response["phKey"]

        response = rrp.hBaseRegOpenKey(
            self.remoteRegistryConnection,
            rootKeyHandle,
            subKeys,
            dwOptions=rrp.REG_OPTION_BACKUP_RESTORE,
            samDesired=READ_CONTROL | rrp.KEY_SET_VALUE | rrp.KEY_CREATE_SUB_KEY,
        )

        targetKeyHandle = response["phkResult"]

        response = rrp.hBaseRegSetValue(
            self.remoteRegistryConnection,
            targetKeyHandle,
            valueName,
            rrp.REG_SZ,
            data + "\x00",
        )

        if response["ErrorCode"] != 0:
            logging.error(f"Failed setting registry key {path} value for {valueName}")

        return

    def deleteKey(self, path: str) -> None:
        # First, let's get the root key that is queried.
        try:
            rootKey, subKeys = path.split("\\", 1)
        except ValueError as e:
            raise e

        # Now let's open the corresponding registry hive
        if rootKey.upper() == "HKLM":
            response = rrp.hOpenLocalMachine(self.remoteRegistryConnection)
        elif rootKey.upper() == "HKU":
            response = rrp.hOpenUsers(self.remoteRegistryConnection)
        elif rootKey.upper() == "HKCR":
            response = rrp.hOpenClassesRoot(self.remoteRegistryConnection)
        else:
            logging.error("Invalid root key")
            raise "Invalid root key"

        rootKeyHandle = response["phKey"]

        try:
            rrp.hBaseRegDeleteKey(self.remoteRegistryConnection, rootKeyHandle, subKeys)
        except Exception as e:
            raise e

        return

    def getKeyValues(self, path: str) -> dict[str, tuple[int, str]]:
        # First, let's get the root key that is queried.
        try:
            rootKey, subKeys = path.split("\\", 1)
        except ValueError as e:
            raise e

        # Now let's open the corresponding registry hive
        if rootKey.upper() == "HKLM":
            response = rrp.hOpenLocalMachine(self.remoteRegistryConnection)
        elif rootKey.upper() == "HKU":
            response = rrp.hOpenUsers(self.remoteRegistryConnection)
        elif rootKey.upper() == "HKCR":
            response = rrp.hOpenClassesRoot(self.remoteRegistryConnection)
        else:
            logging.error("Invalid root key")
            raise ("Invalid root key")

        rootKeyHandle = response["phKey"]

        response = rrp.hBaseRegOpenKey(
            self.remoteRegistryConnection,
            rootKeyHandle,
            subKeys,
            samDesired=rrp.MAXIMUM_ALLOWED
            | rrp.KEY_ENUMERATE_SUB_KEYS
            | rrp.KEY_QUERY_VALUE,
        )

        targetKeyHandle = response["phkResult"]

        index = 0
        output = {}
        while True:
            try:
                response = rrp.hBaseRegEnumValue(
                    self.remoteRegistryConnection, targetKeyHandle, index
                )
                valueName = response["lpValueNameOut"][:-1]

                if len(valueName) == 0:
                    valueName = "(Default)"

                valueType = response["lpType"]
                valueData = b"".join(response["lpData"])

                parsedValueData = self.parseValueDataByType(valueType, valueData)
                output[valueName] = (valueType, parsedValueData)

            except rrp.DCERPCSessionError as e:
                break

            index += 1

        return output

    def getRegistryKeyOwner(self, path):
        # First, let's get the root key that is queried.
        try:
            rootKey, subKeys = path.split("\\", 1)
        except ValueError:
            raise ("Invalid Path")

        # Now let's open the corresponding registry hive
        if rootKey.upper() == "HKLM":
            response = rrp.hOpenLocalMachine(self.remoteRegistryConnection)
        elif rootKey.upper() == "HKU":
            response = rrp.hOpenUsers(self.remoteRegistryConnection)
        elif rootKey.upper() == "HKCR":
            response = rrp.hOpenClassesRoot(self.remoteRegistryConnection)
        else:
            logging.error("Invalid root key")
            raise ("Invalid root key")

        rootKeyHandle = response["phKey"]

        # We need to open the key with REG_OPTION_BACKUP_RESTORE for entries in HKCR, because we do not own the key or have privileges to modify it

        response = rrp.hBaseRegOpenKey(
            self.remoteRegistryConnection,
            rootKeyHandle,
            subKeys,
            dwOptions=rrp.REG_OPTION_BACKUP_RESTORE,
            samDesired=rrp.MAXIMUM_ALLOWED
            | rrp.KEY_ENUMERATE_SUB_KEYS
            | rrp.KEY_QUERY_VALUE,
        )

        targetKeyHandle = response["phkResult"]

        try:
            rrp.hBaseRegSetValue(self.remoteRegistryConnection, targetKeyHandle, "")
        except Exception as e:
            raise (e)

        return

    def parseValueDataByType(self, valueType, valueData):
        try:
            if valueType == rrp.REG_SZ or valueType == rrp.REG_EXPAND_SZ:
                if type(valueData) is int:
                    return "NULL"
                else:
                    return valueData.decode("utf-16le").rstrip("\x00")

            elif valueType == rrp.REG_DWORD:
                return unpack("<L", valueData)[0]
            elif valueType == rrp.REG_QWORD:
                return unpack("<Q", valueData)[0]
            elif valueType == rrp.REG_MULTI_SZ:
                return valueData.decode("utf-16le")[:-2]
            else:
                logging.warning("Unknown reg value type")

        except Exception as e:
            logging.debug("Exception thrown when printing reg value %s" % str(e))
            return
