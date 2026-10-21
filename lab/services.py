"""Per-tier config generation and daemon launch (plant / line / machine / leaf)."""

import json
from pathlib import Path
from string import Template


class ServiceBuilder():

    def __init__(self, shell, topology, daemons, network, output_dir:Path,
                 templates_dir:Path, run_user:str):
        self.shell = shell
        self.topo = topology
        self.daemons = daemons
        self.network = network
        self.output_dir = Path(output_dir)
        self.templates_dir = Path(templates_dir)
        self.run_user = run_user
        self.pd_hook = self._make_pd_hook()

    # ---- helpers -------------------------------------------------------------

    def _tmpl(self, name:str) -> Template:
        return Template((self.templates_dir / name).read_text())

    def _kea_dirs(self) -> dict:
        return {
            "KEA_DHCP_DATA_DIR": str(self.output_dir),
            "KEA_LOG_FILE_DIR": str(self.output_dir),
            "DHCP_DATA_DIR": str(self.output_dir),
        }

    def _make_pd_hook(self) -> Path:
        # odhcp6c calls this on each lease; it logs the delegated prefix as proof of PD.
        pd_hook_file = self.output_dir / "pd-hook.sh"
        with open(pd_hook_file, "w") as fp:
            fp.write(self._tmpl("pd-hook.sh.tmpl").substitute(outdir=str(self.output_dir)))
        self.shell.run(["chmod", "+x", str(pd_hook_file)])
        return pd_hook_file

    def _bind_conf(self, ns, zones:str, include:str="") -> Path:
        name = ns.ns_id
        bind_conf_dir = self.output_dir / f"{name}-bind"
        bind_conf_dir.mkdir(parents=True, exist_ok=True)
        content = self._tmpl("named.conf.tmpl").substitute(
            include=include, directory=str(bind_conf_dir),
            pidfile=f"{self.output_dir}/{name}-named.pid",
            sessionkey=f"{self.output_dir}/{name}-session.key", zones=zones)
        conf = self.output_dir / f"{name}-named.conf"
        with open(conf, "w") as fp:
            fp.write(content)
        return conf

    def _make_key(self, keyname:str):
        # Idempotent TSIG keygen; the orchestrator plays the out-of-band provisioning role,
        # dropping the shared key where both the parent (grant) and the child (nsupdate) read it.
        keyfile = self.output_dir / f"{keyname}.key"
        if not keyfile.is_file():
            with open(keyfile, "w") as fp:
                fp.write(self.shell.capture(["tsig-keygen", "-a", "hmac-sha256", keyname]))
        return keyname, keyfile

    def _delegating_bind_conf(self, ns, ns1_addr:str):
        # Apex-only *dynamic* master zone. Each child gets a TSIG identity allowed to write ONLY
        # its own delegation subtree, so children self-register their NS + glue at runtime.
        db = self.output_dir / f"{ns.ns_id}-db"
        with open(db, "w") as fp:
            fp.write(self._tmpl("db_apex.tmpl").substitute(zone=ns.zone, ns1_addr=ns1_addr))
        grants, includes = [], []
        for child in self.topo.children(ns):
            keyname, keyfile = self._make_key(f"{child.ns_id}-deleg")
            grants.append(f"        grant {keyname} subdomain {child.zone}. NS AAAA;")
            includes.append(f'include "{keyfile}";\n')
        # This tier may write its OWN apex AAAA (its name in the hierarchy) at runtime.
        selfname, selffile = self._make_key(f"{ns.ns_id}-self")
        grants.append(f"        grant {selfname} name {ns.zone}. AAAA;")
        includes.append(f'include "{selffile}";\n')
        zones = self._tmpl("zone_delegating.tmpl").substitute(
            zone=ns.zone, db=str(db), grants="\n".join(grants)).rstrip("\n")
        return self._bind_conf(ns, zones, include="".join(includes))

    def _spawn_registrar(self, ns):
        # This tier learns its parent domain from the DHCPv6 domain-search option (captured by the
        # PD hook), then registers its own NS + glue into the parent zone with a signed DNS UPDATE.
        _, keyfile = self._make_key(f"{ns.ns_id}-deleg")
        up_if = self.topo.wire_names(self.topo.by_id(ns.parent), ns)[1]
        reg = self.output_dir / f"{ns.ns_id}-deleg-register.sh"
        with open(reg, "w") as fp:
            fp.write(self._tmpl("deleg-register.sh.tmpl").substitute(
                label=self.topo.label(ns), key=str(keyfile), up_if=up_if, outdir=str(self.output_dir)))
        reg.chmod(0o755)
        self.daemons.spawn(ns.ns_id, [str(reg)])

    def _apex_addr(self, ns) -> str:
        # Address published at a tier's own zone apex (its name in the hierarchy).
        if ns.parent is None:
            return f"{self.topo.children(ns)[0].transit}1"
        if self.topo.is_machine(ns):
            return f"{self.topo.prefix(ns)[0]}1"
        return f"{ns.transit}2"

    def _spawn_apex_register(self, ns):
        # The tier publishes its own name (zone apex AAAA) into its own dynamic zone via a signed
        # nsupdate -- the leaf's DDNS mechanism applied to the intermediate tiers.
        _, keyfile = self._make_key(f"{ns.ns_id}-self")
        reg = self.output_dir / f"{ns.ns_id}-apex-register.sh"
        with open(reg, "w") as fp:
            fp.write(self._tmpl("apex-register.sh.tmpl").substitute(
                zone=ns.zone, addr=self._apex_addr(ns), key=str(keyfile)))
        reg.chmod(0o755)
        self.daemons.spawn(ns.ns_id, [str(reg)])

    # ---- dispatch ------------------------------------------------------------

    def start_all(self):
        for a_ns in self.topo.namespaces:
            if a_ns.parent is None:
                self.start_root(a_ns)
            elif self.topo.is_leaf(a_ns):
                self.start_leaf(a_ns)
            elif self.topo.is_machine(a_ns):
                self.start_machine(a_ns)
            else:
                self.start_router(a_ns)

    # ---- tiers ---------------------------------------------------------------

    def start_root(self, ns):
        # Step 4: plant delegates a /56 to the line and owns the root DNS zone. The child injects
        # its own delegation into this zone at runtime (dynamic apex zone below).
        child = self.topo.children(ns)[0]
        c_if, _ = self.topo.wire_names(ns, child)
        cprefix, clen = self.topo.prefix(child)
        kea = self.output_dir / f"{ns.ns_id}-kea6.json"
        with open(kea, "w") as fp:
            fp.write(json.dumps({"Dhcp6": {
                "interfaces-config": {"interfaces": [c_if]},
                "lease-database": {"type": "memfile", "name": f"{self.output_dir}/{ns.ns_id}-leases6.csv"},
                "subnet6": [{
                    "id": 1, "subnet": f"{child.transit}/64", "interface": c_if,
                    "pd-pools": [{"prefix": f"{self.topo.ULA_BASE}::", "prefix-len": 48, "delegated-len": clen}],
                    "reservations": [{"duid": self.topo.duid(child), "prefixes": [f"{cprefix}/{clen}"]}]
                }],
                "option-data": [{"name": "domain-search", "data": ns.zone}]}}, indent=2))

        # DNS: apex-only dynamic zone; the child self-delegates via nsupdate.
        conf = self._delegating_bind_conf(ns, ns1_addr=f"{child.transit}1")

        # named drops privileges to the file-owning user so it can read configs in $HOME.
        self.daemons.spawn(ns.ns_id, ["named", "-c", str(conf), "-f", "-u", self.run_user])
        self.daemons.spawn(ns.ns_id, ["kea-dhcp6", "-c", str(kea)], env_dict=self._kea_dirs())
        self.daemons.spawn(ns.ns_id, ["lldpd", "-d", "-u", f"{self.output_dir}/{ns.ns_id}-lldpd.sock"])
        self._spawn_apex_register(ns)

    def start_router(self, ns):
        # Step 5: line tier pulls its /56 upstream, delegates a /64 per child, delegates DNS.
        _, up_if = self.topo.wire_names(self.topo.by_id(ns.parent), ns)
        pprefix, plen = self.topo.prefix(ns)
        self.daemons.spawn(ns.ns_id, [str(self.output_dir / "odhcp6c"), "-N", "none", "-P", str(plen),
                                      "-c", self.topo.duid(ns).replace(":", ""), "-r", "24",
                                      "-s", str(self.pd_hook), up_if])

        subnets = []
        child_ifaces = []
        for i, child in enumerate(self.topo.children(ns), start=1):
            c_if, _ = self.topo.wire_names(ns, child)
            child_ifaces.append(c_if)
            cprefix, clen = self.topo.prefix(child)
            subnets.append({
                "id": i, "subnet": f"{child.transit}/64", "interface": c_if,
                "pd-pools": [{"prefix": pprefix, "prefix-len": plen, "delegated-len": clen}],
                "reservations": [{"duid": self.topo.duid(child), "prefixes": [f"{cprefix}/{clen}"]}]})

        kea = self.output_dir / f"{ns.ns_id}-kea6.json"
        with open(kea, "w") as fp:
            fp.write(json.dumps({"Dhcp6": {
                "interfaces-config": {"interfaces": child_ifaces},
                "lease-database": {"type": "memfile", "name": f"{self.output_dir}/{ns.ns_id}-leases6.csv"},
                "subnet6": subnets,
                "option-data": [{"name": "domain-search", "data": ns.zone}]}}, indent=2))

        # DNS: apex-only dynamic zone; children self-delegate. Advertise our zone downstream and
        # register OUR OWN delegation up into the parent.
        conf = self._delegating_bind_conf(ns, ns1_addr=f"{ns.transit}2")

        self.daemons.spawn(ns.ns_id, ["named", "-c", str(conf), "-f", "-u", self.run_user])
        self.daemons.spawn(ns.ns_id, ["kea-dhcp6", "-c", str(kea)], env_dict=self._kea_dirs())
        self.daemons.spawn(ns.ns_id, ["lldpd", "-d", "-u", f"{self.output_dir}/{ns.ns_id}-lldpd.sock"])
        self._spawn_registrar(ns)
        self._spawn_apex_register(ns)

    def start_machine(self, ns):
        # Step 6: machine tier does RA (Managed), leases an address, and DDNS-registers the leaf.
        _, up_if = self.topo.wire_names(self.topo.by_id(ns.parent), ns)
        prefix, length = self.topo.prefix(ns)
        leaves = self.topo.children(ns)
        leaf_ifs = [self.topo.leaf_if(ns, leaf)[0] for leaf in leaves]

        self.daemons.spawn(ns.ns_id, [str(self.output_dir / "odhcp6c"), "-N", "none", "-P", str(length),
                                      "-c", self.topo.duid(ns).replace(":", ""), "-r", "24",
                                      "-s", str(self.pd_hook), up_if])

        # TSIG key: only signed DNS UPDATEs may touch the zones.
        key = self.shell.netns_capture(ns.ns_id, ["tsig-keygen", "-a", "hmac-sha256", "ddns-key"])
        with open(self.output_dir / f"{ns.ns_id}-ddns.key", "w") as fp:
            fp.write(key)
        secret = ""
        for a_line in key.splitlines():
            if "secret" in a_line:
                secret = a_line.split('"')[1]
        # Kea 3.x rejects clear-text TSIG secrets; hand it a locked-down secret-file.
        secret_file = self.output_dir / f"{ns.ns_id}-ddns.secret"
        with open(secret_file, "w") as fp:
            fp.write(secret)
        secret_file.chmod(0o600)

        # Bridge every leaf link into one L2 segment so a single /64 pool serves all devices
        # (sequential ::100, ::101, ...). Each per-leaf transit gateway moves onto the bridge so
        # the leaves' upstream default routes and the transit reachability checks keep working.
        br = f"{ns.ns_id}-br"[:15]
        self.shell.netns(ns.ns_id, ["ip", "link", "add", br, "type", "bridge"])
        self.shell.netns(ns.ns_id, ["ip", "link", "set", br, "up"])
        for leaf, lf_if in zip(leaves, leaf_ifs):
            self.shell.netns(ns.ns_id, ["ip", "addr", "flush", "dev", lf_if])
            self.shell.netns(ns.ns_id, ["ip", "link", "set", lf_if, "master", br])
            self.shell.netns(ns.ns_id, ["ip", "-6", "addr", "add", f"{leaf.transit}1/64", "dev", br, "nodad"])
        self.shell.netns(ns.ns_id, ["ip", "-6", "addr", "add", f"{prefix}1/64", "dev", br, "nodad"])
        self.network.wait_for_dad(ns.ns_id, br)

        radvd = self.output_dir / f"{ns.ns_id}-radvd.conf"
        with open(radvd, "w") as fp:
            fp.write(self._tmpl("radvd.conf.tmpl").substitute(iface=br, prefix=prefix))

        kea = self.output_dir / f"{ns.ns_id}-kea6.json"
        with open(kea, "w") as fp:
            fp.write(json.dumps({"Dhcp6": {
                "interfaces-config": {"interfaces": [br]},
                "lease-database": {"type": "memfile", "name": f"{self.output_dir}/{ns.ns_id}-leases6.csv"},
                "subnet6": [{"id": 1, "subnet": f"{prefix}/64", "interface": br,
                             "pools": [{"pool": f"{prefix}100 - {prefix}1ff"}]}],
                "dhcp-ddns": {"enable-updates": True, "server-ip": "127.0.0.1", "server-port": 53001},
                "ddns-send-updates": True,
                "ddns-override-client-update": True,
                "ddns-replace-client-name": "when-not-present",
                "ddns-qualifying-suffix": ns.zone}}, indent=2))

        d2 = self.output_dir / f"{ns.ns_id}-d2.json"
        with open(d2, "w") as fp:
            fp.write(json.dumps({"DhcpDdns": {
                "ip-address": "127.0.0.1", "port": 53001,
                "tsig-keys": [{"name": "ddns-key", "algorithm": "HMAC-SHA256", "secret-file": str(secret_file)}],
                "forward-ddns": {"ddns-domains": [{"name": f"{ns.zone}.", "key-name": "ddns-key",
                                 "dns-servers": [{"ip-address": "127.0.0.1", "port": 53}]}]},
                "reverse-ddns": {"ddns-domains": [{"name": f"{self.topo.reverse_zone(ns)}.", "key-name": "ddns-key",
                                 "dns-servers": [{"ip-address": "127.0.0.1", "port": 53}]}]}}}, indent=2))

        with open(self.output_dir / f"{ns.ns_id}-db.fwd", "w") as fp:
            fp.write(self._tmpl("db_forward.tmpl").substitute(zone=ns.zone, addr=f"{prefix}1"))
        with open(self.output_dir / f"{ns.ns_id}-db.rev", "w") as fp:
            fp.write(self._tmpl("db_reverse.tmpl").substitute(zone=ns.zone))
        selfname, selffile = self._make_key(f"{ns.ns_id}-self")
        zones = self._tmpl("zone_dynamic.tmpl").substitute(
            zone=ns.zone, fwd=f"{self.output_dir}/{ns.ns_id}-db.fwd",
            reverse=self.topo.reverse_zone(ns), rev=f"{self.output_dir}/{ns.ns_id}-db.rev",
            selfkey=selfname).rstrip("\n")
        conf = self._bind_conf(ns, zones,
            include=f'include "{self.output_dir}/{ns.ns_id}-ddns.key";\n'
                    f'include "{selffile}";\n')

        # D2 must be up before kea-dhcp6 so the first lease's update is not dropped.
        self.daemons.spawn(ns.ns_id, ["named", "-c", str(conf), "-f", "-u", self.run_user])
        self.daemons.spawn(ns.ns_id, ["kea-dhcp-ddns", "-c", str(d2)], env_dict=self._kea_dirs())
        self.daemons.spawn(ns.ns_id, ["kea-dhcp6", "-c", str(kea)], env_dict=self._kea_dirs())
        self.daemons.spawn(ns.ns_id, ["radvd", "-C", str(radvd),
                                      "-p", f"{self.output_dir}/{ns.ns_id}-radvd.pid", "-n"])
        self.daemons.spawn(ns.ns_id, ["lldpd", "-d", "-u", f"{self.output_dir}/{ns.ns_id}-lldpd.sock"])
        # Register OUR OWN delegation (sift.fcl…) up into the parent (fcl) via signed nsupdate.
        self._spawn_registrar(ns)
        self._spawn_apex_register(ns)

    def start_leaf(self, ns):
        # Step 7: the device knows only its label. It sends a PARTIAL Client-FQDN and the machine's
        # Kea appends ddns-qualifying-suffix to form the full name and DDNS-register it.
        short = self.topo.label(ns)
        conf = self.output_dir / f"{ns.ns_id}-dhclient6.conf"
        with open(conf, "w") as fp:
            fp.write(self._tmpl("dhclient6.conf.tmpl").substitute(label=short, labellen=len(short)))
        # avahi's runtime dir (/run/avahi-daemon) is shared across net namespaces, so a second
        # instance sees the first's pid; give each leaf a private one via a mount ns + tmpfs.
        # D-Bus is disabled in the config since there is no per-namespace system bus.
        avahi_conf = self.output_dir / f"{ns.ns_id}-avahi.conf"
        with open(avahi_conf, "w") as fp:
            fp.write(self._tmpl("avahi-daemon.conf.tmpl").substitute(host=short))
        self.daemons.spawn(ns.ns_id, ["unshare", "--mount", "--propagation", "private", "sh", "-c",
                                      "mkdir -p /run/avahi-daemon && mount -t tmpfs tmpfs /run/avahi-daemon "
                                      f"&& exec avahi-daemon --no-drop-root --no-rlimits -f {avahi_conf}"])
        self.network.wait_for_dad(ns.ns_id, "eth0")
        self.daemons.spawn(ns.ns_id, ["dhclient", "-6", "-v", "-cf", str(conf),
                                      "-lf", f"{self.output_dir}/{ns.ns_id}-lease6",
                                      "-pf", f"{self.output_dir}/{ns.ns_id}-dhclient6.pid", "eth0"])
