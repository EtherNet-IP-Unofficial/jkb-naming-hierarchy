"""Kernel plumbing: namespaces, veth wires, routes and DAD waiting."""

from time import sleep


class NetworkBuilder():

    def __init__(self, shell, topology):
        self.shell = shell
        self.topo = topology

    # ---- namespaces + forwarding --------------------------------------------

    def register_namespaces(self):
        # Every namespace can run a kernel networking stack.
        for a_ns in self.topo.namespaces:
            self.shell.run(["ip", "netns", "add", a_ns.ns_id], sudo=True)
            self.shell.run(["ip", "-n", a_ns.ns_id, "link", "set", "lo", "up"], sudo=True)
        self.shell.run(["ip", "netns", "list"], sudo=True)

    def enable_forwarding(self):
        for a_ns in self.topo.namespaces:
            if not self.topo.is_leaf(a_ns):
                print(f"Enabling forwarding on {a_ns.ns_id}")
                # sysctl -w writes a kernel tunable quietly; makes the namespace a router.
                self.shell.netns(a_ns.ns_id,
                                 ["sysctl", "-q", "-w", "net.ipv6.conf.all.forwarding=1"])

    # ---- veth wires ----------------------------------------------------------

    def create_wires(self):
        for a_wire in self.topo.wires():
            parent, a_ns = a_wire.parent, a_wire.child
            p_if, c_if = a_wire.parent_if, a_wire.child_if
            print(f"Wiring {parent.ns_id} <-> {a_ns.ns_id} on {a_ns.transit}/64")
            # A veth pair is a virtual cable: parent end in parent ns, child end in child ns.
            self.shell.run(["ip", "link", "add", p_if, "netns", parent.ns_id,
                            "type", "veth", "peer", "name", c_if, "netns", a_ns.ns_id], sudo=True)
            self.shell.run(["ip", "-n", parent.ns_id, "link", "set", p_if, "up"], sudo=True)
            self.shell.run(["ip", "-n", a_ns.ns_id, "link", "set", c_if, "up"], sudo=True)
            # ::1 is the upper (parent) end, ::2 the lower (child) end.
            self.shell.run(["ip", "-n", parent.ns_id, "addr", "add",
                            f"{a_ns.transit}1/64", "dev", p_if], sudo=True)
            self.shell.run(["ip", "-n", a_ns.ns_id, "addr", "add",
                            f"{a_ns.transit}2/64", "dev", c_if], sudo=True)

    def destroy_wires(self):
        for a_wire in self.topo.wires():
            # Deleting one end of a veth pair removes the whole cable.
            self.shell.run(["ip", "-n", a_wire.parent.ns_id, "link", "del", a_wire.parent_if], sudo=True)

    # ---- routes --------------------------------------------------------------

    def create_routes(self):
        # PD delegates addresses, not reachability; add the return routes by hand.
        for a_ns in self.topo.namespaces:
            if a_ns.parent is None:
                continue
            parent = self.topo.by_id(a_ns.parent)
            # Child's default route points up to the parent transit ::1.
            self.shell.run(["ip", "-n", a_ns.ns_id, "route", "add", "default",
                            "via", f"{a_ns.transit}1"], sudo=True)
            if self.topo.is_leaf(a_ns):
                continue
            prefix, length = self.topo.prefix(a_ns)
            # Parent reaches the child's delegated block via the child transit ::2.
            self.shell.run(["ip", "-n", parent.ns_id, "route", "add", f"{prefix}/{length}",
                            "via", f"{a_ns.transit}2"], sudo=True)

    # ---- DAD -----------------------------------------------------------------

    def wait_for_dad(self, ns_id:str, iface:str|None=None, tries:int=10) -> None:
        # Daemons that bind a link-local (Kea, odhcp6c, radvd, dhclient) fail while any
        # address is still tentative; wait for DAD to clear. dad usually takes 1s.
        scope = ["dev", iface] if iface else []
        for _ in range(tries):
            tentative = self.shell.netns_capture(
                ns_id, ["ip", "-6", "-o", "addr", "show", *scope, "tentative"])
            if not tentative.strip():
                return
            sleep(0.6)

    def wait_all_dad(self) -> None:
        for a_ns in self.topo.namespaces:
            self.wait_for_dad(a_ns.ns_id)

    # ---- teardown ------------------------------------------------------------

    def kill_stragglers(self):
        for a_ns in self.topo.namespaces:
            # Kill anything still bound inside the namespace before it is deleted.
            self.shell.run(["sh", "-c",
                            f"ip netns pids {a_ns.ns_id} 2>/dev/null | xargs -r kill 2>/dev/null || true"],
                           sudo=True)

    def unregister_namespaces(self):
        for a_ns in self.topo.namespaces:
            self.shell.run(["ip", "-n", a_ns.ns_id, "link", "set", "lo", "down"], sudo=True)
            self.shell.run(["ip", "netns", "del", a_ns.ns_id], sudo=True)
        self.shell.run(["ip", "netns", "list"], sudo=True)
