"""Pure topology model: namespaces, naming, prefixes and wires (no side effects)."""

import ipaddress
import json
from pathlib import Path

from models import Namespace, Wire


class Topology():

    ULA = "fd12:3456:789a::/48"
    """Base /48; hextet 4 is filled from the tier subnets (MANUAL 'What you are building')."""
    ULA_BASE = "fd12:3456:789a"

    DEFAULT = [
        Namespace(ns_id="plant", zone="plant.cake.inc", description="Plant Namespace", tier=0, subnet=0xa),
        Namespace(ns_id="fcl", zone="fcl.plant.cake.inc", description="Flour Calibration Line Namespace", tier=1, subnet=3, parent="plant", transit="fd12:3456:789a:ff03::"),
        Namespace(ns_id="sift", zone="sift.fcl.plant.cake.inc", description="Sifter Machine Namespace", tier=2, subnet=1, parent="fcl", transit="fd12:3456:789a:03ff::"),
        Namespace(ns_id="dev-1", zone="dev1.sift.fcl.plant.cake.inc", description="Device 1 Namespace", tier=3, subnet=None, parent="sift", transit="fd12:3456:789a:01fe::"),
        Namespace(ns_id="dev-2", zone="dev2.sift.fcl.plant.cake.inc", description="Device 2 Namespace", tier=3, subnet=None, parent="sift", transit="fd12:3456:789a:01fd::"),
    ]

    def __init__(self, namespaces:list|None=None, json_config:Path|None=None):
        self.namespaces = namespaces if namespaces is not None else [n for n in Topology.DEFAULT]
        if json_config:
            self._load(json_config)
        self._by_id = {a_ns.ns_id: a_ns for a_ns in self.namespaces}
        self.root = next(a_ns for a_ns in self.namespaces if a_ns.parent is None)
        self._verify_names()

    def _load(self, filename:Path) -> None:
        if filename and Path(filename).is_file():
            with open(filename, "r") as fp:
                config = json.load(fp)
            self.namespaces = [Namespace(**a_dev) for a_dev in config]

    # ---- lookups -------------------------------------------------------------

    def by_id(self, ns_id:str) -> Namespace:
        return self._by_id[ns_id]

    def children(self, ns:Namespace) -> list:
        return [c for c in self.namespaces if c.parent == ns.ns_id]

    def is_leaf(self, ns:Namespace) -> bool:
        return ns.subnet is None

    def is_machine(self, ns:Namespace) -> bool:
        # A machine tier is a router whose children are all leaves.
        kids = self.children(ns)
        return bool(kids) and all(self.is_leaf(c) for c in kids)

    # ---- addressing / naming -------------------------------------------------

    def prefix(self, ns:Namespace) -> tuple[str, int]:
        # Hextet 4 encodes position: tier1 subnet is the high byte, tier2 the low byte.
        if ns.parent is None:
            return f"{self.ULA_BASE}::", 48
        if ns.parent == self.root.ns_id:
            return f"{self.ULA_BASE}:{ns.subnet:02x}00::", 56
        parent = self._by_id[ns.parent]
        return f"{self.ULA_BASE}:{parent.subnet:02x}{ns.subnet:02x}::", 64

    def reverse_zone(self, ns:Namespace) -> str:
        prefix, length = self.prefix(ns)
        net = ipaddress.ip_network(f"{prefix}/{length}")
        # Keep only the prefix nibbles (length/4), reversed, as the ip6.arpa zone.
        nibbles = net.network_address.exploded.replace(":", "")[:length // 4]
        return ".".join(reversed(nibbles)) + ".ip6.arpa"

    def duid(self, ns:Namespace) -> str:
        # Deterministic DUID keyed by the namespace subnet byte ("config by location").
        return f"00:03:00:01:02:00:00:00:03:{(ns.subnet or 0):02x}"

    def label(self, ns:Namespace) -> str:
        return ns.zone.split(".")[0]

    def wire_names(self, parent:Namespace, child:Namespace) -> tuple[str, str]:
        # Kernel caps interface names at 15 chars.
        return f"{parent.ns_id}-{child.ns_id}"[:15], f"{child.ns_id}-{parent.ns_id}"[:15]

    def leaf_if(self, machine:Namespace, leaf:Namespace) -> tuple[str, str]:
        # Machine end combines both names (like a wire) so sibling leaves don't
        # collide; the leaf's own NIC is always eth0 (MANUAL naming convention).
        machine_if, _ = self.wire_names(machine, leaf)
        return machine_if, "eth0"

    def pair_names(self, parent:Namespace, child:Namespace) -> tuple[str, str]:
        if self.is_leaf(child):
            return self.leaf_if(parent, child)
        return self.wire_names(parent, child)

    def wires(self) -> list:
        # Every parent<->child veth cable, in build order.
        result = []
        for a_ns in self.namespaces:
            if a_ns.parent is None:
                continue
            parent = self._by_id[a_ns.parent]
            p_if, c_if = self.pair_names(parent, a_ns)
            result.append(Wire(parent=parent, child=a_ns, parent_if=p_if,
                               child_if=c_if, transit=a_ns.transit))
        return result

    def _verify_names(self):
        # Two short names join with a dash into one interface; keep each <=7 so
        # the pair stays within the 15-char kernel limit.
        for a_ns in self.namespaces:
            assert len(a_ns.ns_id) <= 7, f"ns_id '{a_ns.ns_id}' exceeds 7 chars"
