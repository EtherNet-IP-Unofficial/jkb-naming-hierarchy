"""End-to-end checks with explicit expected-vs-actual output."""

import ipaddress
from time import sleep


class Verifier():

    def __init__(self, shell, topology, output_dir):
        self.shell = shell
        self.topo = topology
        self.output_dir = output_dir

    # ---- probes --------------------------------------------------------------

    def _retry(self, produce, ok, tries:int=15, delay:float=1.0):
        # Poll an async result (DHCP lease, DDNS record) until it settles or we give up.
        value = produce()
        for _ in range(tries):
            if ok(value):
                return value
            sleep(delay)
            value = produce()
        return value

    def _iface_global6(self, ns_id:str, iface:str) -> str|None:
        # First global-scope IPv6 address on the interface (the DHCPv6 lease), sans prefixlen.
        out = self.shell.netns_capture(
            ns_id, ["ip", "-6", "-o", "addr", "show", "dev", iface, "scope", "global"])
        for token in out.split():
            if ":" in token and "/" in token:
                return token.split("/")[0]
        return None

    def _dig(self, ns_id:str, *args:str) -> str:
        return self.shell.netns_capture(ns_id, ["dig", "+short", "@::1", *args]).strip()

    def _pd_logged_prefix(self, iface:str) -> str:
        # Last prefix odhcp6c recorded through the PD hook for this interface. odhcp6c appends
        # lifetimes as 'prefix/len,preferred,valid,...', so keep only the prefix itself.
        log = self.shell.capture(["sh", "-c", f"cat {self.output_dir}/{iface}.pdlog 2>/dev/null"], sudo=True)
        got = ""
        for a_line in log.splitlines():
            for tok in a_line.split():
                if ":" in tok and "/" in tok:
                    got = tok.split(",")[0]
        return got

    def _apex_addr(self, ns) -> str:
        # The address published at a tier's own zone apex (mirrors services.py).
        if ns.parent is None:
            return f"{self.topo.children(ns)[0].transit}1"
        if self.topo.is_machine(ns):
            return f"{self.topo.prefix(ns)[0]}1"
        return f"{ns.transit}2"

    def _gather_addrs(self) -> dict:
        # Every global-scope IPv6 address per namespace (leases, transits, bridge gateways).
        addrs = {}
        for a_ns in self.topo.namespaces:
            out = self.shell.netns_capture(
                a_ns.ns_id, ["ip", "-6", "-o", "addr", "show", "scope", "global"])
            found = []
            for tok in out.split():
                if ":" in tok and "/" in tok:
                    a = tok.split("/")[0]
                    try:
                        ipaddress.ip_address(a)
                        found.append(a)
                    except ValueError:
                        pass
            addrs[a_ns.ns_id] = found
        return addrs

    def _reachability(self, check):
        # Ping every global address in the lab from every other namespace and build a matrix.
        # Source is forced to each namespace's aggregated-hierarchy address so the return path
        # exists; lower-tier transit /64s are intentionally not globally routable (honest bits).
        agg = ipaddress.ip_network(f"{self.topo.ULA_BASE}:0300::/56")
        addrs = self._gather_addrs()

        def source_for(ns_id):
            for a in addrs[ns_id]:
                try:
                    if ipaddress.ip_address(a) in agg:
                        return a
                except ValueError:
                    pass
            return addrs[ns_id][0] if addrs[ns_id] else None

        print("\n---- Reachability: pinging every global address from every namespace ----")
        for a_ns in self.topo.namespaces:
            print(f"   {a_ns.ns_id:<7} {', '.join(addrs[a_ns.ns_id]) or '(none)'}")

        targets = [(nid, a) for nid, lst in addrs.items() for a in lst]
        reach_pairs = total_pairs = 0
        ns_reach = {}
        for a_ns in self.topo.namespaces:
            src = source_for(a_ns.ns_id)
            for dst_ns, dst_addr in targets:
                if dst_ns == a_ns.ns_id:
                    continue
                total_pairs += 1
                ok = False
                if src:
                    out = self.shell.netns_capture(
                        a_ns.ns_id, ["ping", "-6", "-c", "1", "-W", "1", "-I", src, dst_addr])
                    ok = "1 received" in out or " 0% packet loss" in out
                if ok:
                    reach_pairs += 1
                key = (a_ns.ns_id, dst_ns)
                ns_reach[key] = ns_reach.get(key, False) or ok

        ids = [n.ns_id for n in self.topo.namespaces]
        w = max(len(i) for i in ids)
        print("\n   node reachability (source down / target across): '+' reachable, '.' no route")
        print("   " + " " * w + "  " + "  ".join(f"{i:>{w}}" for i in ids))
        for a in ids:
            cells = [("-" if a == b else ("+" if ns_reach.get((a, b)) else ".")).rjust(w) for b in ids]
            print("   " + f"{a:>{w}}" + "  " + "  ".join(cells))
        print(f"\n   address-level reachable pairs: {reach_pairs}/{total_pairs} "
              "(lower-tier transit /64s are intentionally not globally routable)")

        for a in self.topo.namespaces:
            for b in self.topo.namespaces:
                if a.ns_id == b.ns_id:
                    continue
                ok = ns_reach.get((a.ns_id, b.ns_id), False)
                check(f"REACH {a.ns_id} -> {b.ns_id}", "reachable (any address)",
                      "reachable" if ok else "UNREACHABLE", ok)

    # ---- run -----------------------------------------------------------------

    def run(self):
        print("\n================= VERIFICATION =================")
        results = []

        def check(name:str, expected, actual, ok:bool):
            results.append(ok)
            print(f"[{'PASS' if ok else 'FAIL'}] {name}")
            print(f"         expected: {expected}")
            print(f"         actual:   {actual}")

        def same_net(a:str, net) -> bool:
            try:
                return ipaddress.ip_network(a, strict=False) == net
            except ValueError:
                return False

        def in_net(addr, net) -> bool:
            try:
                return ipaddress.ip_address(addr) in net
            except (ValueError, TypeError):
                return False

        def same_addr(a, b) -> bool:
            try:
                return ipaddress.ip_address(a) == ipaddress.ip_address(b)
            except (ValueError, TypeError):
                return False

        # 1) Cascaded DHCPv6-PD: every router/machine pulled its deterministic prefix.
        for a_ns in self.topo.namespaces:
            if a_ns.parent is None or self.topo.is_leaf(a_ns):
                continue
            up_if = self.topo.wire_names(self.topo.by_id(a_ns.parent), a_ns)[1]
            want = ipaddress.ip_network("{}/{}".format(*self.topo.prefix(a_ns)))
            got = self._retry(lambda i=up_if: self._pd_logged_prefix(i), lambda v: same_net(v, want))
            check(f"PD  {a_ns.ns_id} pulls {want}", str(want), got or "(none)", same_net(got, want))

        # 2) Per leaf: leased address in the right /64, plus forward AAAA and reverse PTR.
        for a_ns in self.topo.namespaces:
            if not self.topo.is_machine(a_ns):
                continue
            mnet = ipaddress.ip_network("{}/{}".format(*self.topo.prefix(a_ns)))
            for leaf in self.topo.children(a_ns):
                fqdn = f"{self.topo.label(leaf)}.{a_ns.zone}"
                addr = self._retry(lambda l=leaf: self._iface_global6(l.ns_id, "eth0"),
                                   lambda v: in_net(v, mnet))
                check(f"ADDR  {leaf.ns_id} leased from {mnet}", f"address in {mnet}",
                      addr or "(none)", in_net(addr, mnet))

                fwd = self._retry(lambda f=fqdn, z=a_ns.ns_id: self._dig(z, "AAAA", f),
                                  lambda v: same_addr(v.split("\n")[0] if v else None, addr))
                fwd_first = fwd.split("\n")[0] if fwd else None
                check(f"DNS   {fqdn} AAAA -> lease", addr or "(none)", fwd or "(none)",
                      same_addr(fwd_first, addr))

                rev = self._dig(a_ns.ns_id, "-x", addr) if addr else ""
                check(f"PTR   {addr or '(none)'} -> name", f"{fqdn}.", rev or "(none)",
                      rev.rstrip(".") == fqdn)

        # 2b) Each tier publishes its own name in the hierarchy (talk to intermediates by name).
        for a_ns in self.topo.namespaces:
            if self.topo.is_leaf(a_ns):
                continue
            want = self._apex_addr(a_ns)
            got = self._retry(lambda z=a_ns: self._dig(z.ns_id, z.zone, "AAAA"),
                              lambda v: same_addr(v.split("\n")[0] if v else None, want))
            got_first = got.split("\n")[0] if got else None
            check(f"NAME  {a_ns.zone} AAAA", want, got_first or "(none)",
                  same_addr(got_first, want))

        # 3) Link connectivity: each namespace reaches its upstream gateway.
        for a_ns in self.topo.namespaces:
            if a_ns.parent is None:
                continue
            gw = f"{a_ns.transit}1"
            out = self.shell.netns_capture(a_ns.ns_id, ["ping", "-6", "-c", "2", "-W", "1", gw])
            ok = "0% packet loss" in out
            tail = next((ln.strip() for ln in out.splitlines() if "packet loss" in ln), "(no output)")
            check(f"LINK  {a_ns.ns_id} -> gateway {gw}", "0% packet loss", tail, ok)

        # 4) Full reachability: every global address pinged from every other namespace.
        self._reachability(check)

        passed, total = sum(1 for r in results if r), len(results)
        print("\n" + "=" * 48)
        if passed == total:
            print(f"  SUCCESS  {passed}/{total} checks passed -- cascaded PD, DDNS and routing verified.")
        else:
            print(f"  FAILURE  {passed}/{total} checks passed -- see [FAIL] lines above.")
        print("=" * 48 + "\n")
        return passed == total
