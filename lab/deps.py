"""Check the external tools the lab shells out to are present before building."""

import os
import shutil
from pathlib import Path


class DependencyChecker():

    # Binaries the build/verify/teardown paths shell out to.
    REQUIRED = [
        "ip", "sysctl", "unshare", "mount", "ping", "dig", "tsig-keygen", "nsupdate",
        "named", "kea-dhcp6", "kea-dhcp-ddns", "radvd", "lldpd",
        "avahi-daemon", "dhclient",
    ]
    # Not fatal: the lab still builds/verifies without these.
    OPTIONAL = {
        "tcpdump": "per-wire packet capture (sniffing)",
        "jq": "ad-hoc JSON inspection",
    }

    def __init__(self, shell, output_dir):
        self.shell = shell
        self.output_dir = Path(output_dir)

    def check(self) -> list:
        print("\n================ DEPENDENCIES =================")
        missing = []

        for cmd in [self.shell.sudo_provider, *self.REQUIRED]:
            path = shutil.which(cmd)
            print(f"[{'OK  ' if path else 'FAIL'}] {cmd:<16}{path or '(not found)'}")
            if path is None:
                missing.append(cmd)

        # odhcp6c is a locally-built requesting-router client kept beside the configs.
        odhcp6c = self.output_dir / "odhcp6c"
        odh_ok = odhcp6c.is_file() and os.access(odhcp6c, os.X_OK)
        print(f"[{'OK  ' if odh_ok else 'FAIL'}] {'odhcp6c':<16}{odhcp6c if odh_ok else f'(missing/!x at {odhcp6c})'}")
        if not odh_ok:
            missing.append(str(odhcp6c))

        for cmd, why in self.OPTIONAL.items():
            path = shutil.which(cmd)
            print(f"[{'OK  ' if path else 'warn'}] {cmd:<16}{path or f'(optional: {why})'}")

        print("=" * 47)
        return missing

    def require(self) -> None:
        missing = self.check()
        if missing:
            raise RuntimeError("Missing required dependencies: " + ", ".join(missing))
