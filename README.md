# ThievingFox

ThievingFox is a collection of post-exploitation tools to gather credentials from various password managers and windows utilities.
Each module leverages a specific method of injecting into the target process, and then hooks internals functions to gather crendentials. 

The accompanying blog post can be found [here](https://blog.slowerzs.net/posts/thievingfox)

---

- [Installation](#Installation)
- [Targets](#Targets)
- [Usage](#Usage)

# Installation

## Linux

Rustup must be installed, follow the instructions available here : https://rustup.rs/

The mingw-w64 package must be installed.
On Debian, this can be done using : 
```
apt install mingw-w64
``` 

Both x86 and x86_64 windows targets must be installed for Rust:

```
rustup target add x86_64-pc-windows-gnu
rustup target add i686-pc-windows-gnu
```

Mono and Nuget must also be installed, instructions are available here : https://www.mono-project.com/download/stable/#download-lin

After adding Mono repositories, Nuget can be installed using apt : 
```
apt install nuget
```

Finally, python dependancies must be installed : 
```
pip install -r client/requirements.txt
```

## Windows

Rustup must be installed, follow the instructions available here : https://rustup.rs/


Both x86 and x86_64 windows targets must be installed for Rust:
```
rustup target add x86_64-pc-windows-msvc
rustup target add i686-pc-windows-msvc
```

.NET development environment must also be installed. From Visual Studio, navigate to `Tools > Get Tools And Features > Install ".NET desktop development"`

Finally, python dependancies must be installed : 
```
pip install -r client/requirements.txt
```

> NOTE : On a Windows host, in order to use the KeePass module, msbuild must be available in the PATH. This can be achieved by running the client from within a Visual Studio Developper Powershell (Tools > Command Line > Developper Powershell)

# Targets

All modules have been tested on the following Windows versions :

|Windows Version|
| --- |
|Windows Server 2022|
|Windows Server 2019|
|Windows Server 2016|
|Windows Server 2012R2|
|Windows 10|
|Windows 11|

> [!CAUTION]
> Modules have **not** been tested on other version, and are expected to **not** work.

| Application | Injection Method |
| ---- | ---- |
| KeePass.exe | AppDomainManager Injection |
| KeePassXC.exe | DLL Proxying |
| LogonUI.exe | COM Hijacking |
| consent.exe | COM Hijacking |
| mstsc.exe | COM Hijacking |
| RDCMan.exe | COM Hijacking |
| MobaXTerm.exe | COM Hijacking |

# Usage

> [!CAUTION]
> Although I tried to ensure that these tools do not impact the stability of the targeted applications, inline hooking and library injection are unsafe and this might result in a crash, or the application being unstable. If that were the case, using the `cleanup` module on the target *should* be enough to ensure that the **next** time the application is launched, no injection/hooking is performed.

ThievingFox contains 3 main modules : `poison`, `cleanup` and `collect`.


## Poison

For each application specified in the command line parameters, the `poison` module retrieves the original library that is going to be hijacked (for COM hijacking and DLL proxying), compiles a library that has matches the properties of the original DLL, uploads it to the server, and modify the registry if needed to perform COM hijacking.

To speed up the process of compilation of all libraries, a cache is maintained in `client/cache/`.

`--mstsc`, `--rdcman`, and `--mobaxterm` have a specific option, respectively `--mstsc-poison-hkcr`, `--rdcman-poison-hkcr`, and `--mobaxterm-poison-hkcr`. If one of these options is specified, the COM hijacking will replace the registry key in the `HKCR` hive, meaning all users will be impacted. By default, only all currently logged in users are impacted (all users that have a `HKCU` hive).

`--keepass` and ` --keepassxc` have specific options, `--keepass-path`, `--keepass-share`, and `--keepassxc-path`, `--keepassxc-share`, to specify where these applications are installed, if it's not the default installation path. This is not required for other applications, since COM hijacking is used.

The KeePass modules requires the `Visual C++ Redistributable` to be installed on the target.

Multiple applications can be specified at once, or, the `--all` flag can be used to target all applications.

> [!IMPORTANT]
> Remember to clean the cache if you ever change the `--tempdir` parameter, since the directory name is embedded inside native DLLs.

```
$ python3 client/ThievingFox.py poison -h
usage: ThievingFox.py poison [-h] [-hashes HASHES] [-aesKey AESKEY] [-k] [-dc-ip DC_IP] [-no-pass] [--tempdir TEMPDIR] [--keepass] [--keepass-path KEEPASS_PATH]
                             [--keepass-share KEEPASS_SHARE] [--keepassxc] [--keepassxc-path KEEPASSXC_PATH] [--keepassxc-share KEEPASSXC_SHARE] [--mstsc] [--mstsc-poison-hkcr]
                             [--consent] [--logonui] [--rdcman] [--rdcman-poison-hkcr] [--mobaxterm] [--mobaxterm-poison-hkcr] [--all]
                             target

positional arguments:
  target                Target machine or range [domain/]username[:password]@<IP or FQDN>[/CIDR]

options:
  -h, --help            show this help message and exit
  -hashes HASHES, --hashes HASHES
                        LM:NT hash
  -aesKey AESKEY, --aesKey AESKEY
                        AES key to use for Kerberos Authentication
  -k                    Use kerberos authentication. For LogonUI, mstsc and consent modules, an anonymous NTLM authentication is performed, to retrieve the OS version.
  -dc-ip DC_IP, --dc-ip DC_IP
                        IP Address of the domain controller
  -no-pass, --no-pass   Do not prompt for password
  --tempdir TEMPDIR     The name of the temporary directory to use for DLLs and output (Default: ThievingFox)
  --keepass             Try to poison KeePass.exe
  --keepass-path KEEPASS_PATH
                        The path where KeePass is installed, without the share name (Default: /Program Files/KeePass Password Safe 2/)
  --keepass-share KEEPASS_SHARE
                        The share on which KeePass is installed (Default: c$)
  --keepassxc           Try to poison KeePassXC.exe
  --keepassxc-path KEEPASSXC_PATH
                        The path where KeePassXC is installed, without the share name (Default: /Program Files/KeePassXC/)
  --keepassxc-share KEEPASSXC_SHARE
                        The share on which KeePassXC is installed (Default: c$)
  --mstsc               Try to poison mstsc.exe
  --mstsc-poison-hkcr   Instead of poisonning all currently logged in users' HKCU hives, poison the HKCR hive for mstsc, which will also work for user that are currently not
                        logged in (Default: False)
  --consent             Try to poison Consent.exe
  --logonui             Try to poison LogonUI.exe
  --rdcman              Try to poison RDCMan.exe
  --rdcman-poison-hkcr  Instead of poisonning all currently logged in users' HKCU hives, poison the HKCR hive for RDCMan, which will also work for user that are currently not
                        logged in (Default: False)
  --mobaxterm           Try to poison MobaXTerm.exe
  --mobaxterm-poison-hkcr
                        Instead of poisonning all currently logged in users' HKCU hives, poison the HKCR hive for MobaXTerm, which will also work for user that are currently not
                        logged in (Default: False)
  --all                 Try to poison all applications
```

## Cleanup

For each application specified in the command line parameters, the `cleanup` first removes poisonning artifacts that force the target application to load the hooking library. Then, it tries to delete the library that were uploaded to the remote host.

For applications that support poisonning of both `HKCU` and `HKCR` hives, both are cleaned up regardless.

Multiple applications can be specified at once, or, the `--all` flag can be used to cleanup all applications.

It does not clean extracted credentials on the remote host.

> [!IMPORTANT]
> If the targeted application is in use while the `cleanup` module is ran, the DLL that are dropped on the target cannot be deleted. Nonetheless, the `cleanup` module will revert the configuration that enables the injection, which *should* ensure that the next time the application is launched, no injection is performed. Files that cannot be deleted by `ThievingFox` are logged.

```
$ python3 client/ThievingFox.py cleanup -h
usage: ThievingFox.py cleanup [-h] [-hashes HASHES] [-aesKey AESKEY] [-k] [-dc-ip DC_IP] [-no-pass] [--tempdir TEMPDIR] [--keepass] [--keepass-share KEEPASS_SHARE]
                              [--keepass-path KEEPASS_PATH] [--keepassxc] [--keepassxc-path KEEPASSXC_PATH] [--keepassxc-share KEEPASSXC_SHARE] [--mstsc] [--consent] [--logonui]
                              [--rdcman] [--mobaxterm] [--all]
                              target

positional arguments:
  target                Target machine or range [domain/]username[:password]@<IP or FQDN>[/CIDR]

options:
  -h, --help            show this help message and exit
  -hashes HASHES, --hashes HASHES
                        LM:NT hash
  -aesKey AESKEY, --aesKey AESKEY
                        AES key to use for Kerberos Authentication
  -k                    Use kerberos authentication. For LogonUI, mstsc and consent modules, an anonymous NTLM authentication is performed, to retrieve the OS version.
  -dc-ip DC_IP, --dc-ip DC_IP
                        IP Address of the domain controller
  -no-pass, --no-pass   Do not prompt for password
  --tempdir TEMPDIR     The name of the temporary directory to use for DLLs and output (Default: ThievingFox)
  --keepass             Try to cleanup all poisonning artifacts related to KeePass.exe
  --keepass-share KEEPASS_SHARE
                        The share on which KeePass is installed (Default: c$)
  --keepass-path KEEPASS_PATH
                        The path where KeePass is installed, without the share name (Default: /Program Files/KeePass Password Safe 2/)
  --keepassxc           Try to cleanup all poisonning artifacts related to KeePassXC.exe
  --keepassxc-path KEEPASSXC_PATH
                        The path where KeePassXC is installed, without the share name (Default: /Program Files/KeePassXC/)
  --keepassxc-share KEEPASSXC_SHARE
                        The share on which KeePassXC is installed (Default: c$)
  --mstsc               Try to cleanup all poisonning artifacts related to mstsc.exe
  --consent             Try to cleanup all poisonning artifacts related to Consent.exe
  --logonui             Try to cleanup all poisonning artifacts related to LogonUI.exe
  --rdcman              Try to cleanup all poisonning artifacts related to RDCMan.exe
  --mobaxterm           Try to cleanup all poisonning artifacts related to MobaXTerm.exe
  --all                 Try to cleanup all poisonning artifacts related to all applications
```

## Collect

For each application specified on the command line parameters, the `collect` module retrieves output files on the remote host stored inside `C:\Windows\Temp\<tempdir>` corresponding to the application, and decrypts them. The files are deleted from the remote host, and retrieved data is stored in `client/ouput/`.

Multiple applications can be specified at once, or, the `--all` flag can be used to collect logs from all applications.

```
$ python3 client/ThievingFox.py collect -h
usage: ThievingFox.py collect [-h] [-hashes HASHES] [-aesKey AESKEY] [-k] [-dc-ip DC_IP] [-no-pass] [--tempdir TEMPDIR] [--keepass] [--keepassxc] [--mstsc] [--consent]
                              [--logonui] [--rdcman] [--mobaxterm] [--all]
                              target

positional arguments:
  target                Target machine or range [domain/]username[:password]@<IP or FQDN>[/CIDR]

options:
  -h, --help            show this help message and exit
  -hashes HASHES, --hashes HASHES
                        LM:NT hash
  -aesKey AESKEY, --aesKey AESKEY
                        AES key to use for Kerberos Authentication
  -k                    Use kerberos authentication. For LogonUI, mstsc and consent modules, an anonymous NTLM authentication is performed, to retrieve the OS version.
  -dc-ip DC_IP, --dc-ip DC_IP
                        IP Address of the domain controller
  -no-pass, --no-pass   Do not prompt for password
  --tempdir TEMPDIR     The name of the temporary directory to use for DLLs and output (Default: ThievingFox)
  --keepass             Collect KeePass.exe logs
  --keepassxc           Collect KeePassXC.exe logs
  --mstsc               Collect mstsc.exe logs
  --consent             Collect Consent.exe logs
  --logonui             Collect LogonUI.exe logs
  --rdcman              Collect RDCMan.exe logs
  --mobaxterm           Collect MobaXTerm.exe logs
  --all                 Collect logs from all applications
```
