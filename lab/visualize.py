"""Render the built topology as an ASCII tree and a Mermaid diagram."""

from pathlib import Path


class Visualizer():

    def __init__(self, topology, output_dir, shell=None):
        self.topo = topology
        self.output_dir = Path(output_dir)
        self.shell = shell

    # ---- data ----------------------------------------------------------------

    def _prefix_str(self, ns) -> str:
        if self.topo.is_leaf(ns):
            return "leaf"
        prefix, length = self.topo.prefix(ns)
        return f"{prefix}/{length}"

    def _leased(self, ns) -> str:
        # Live global address on a leaf's eth0, if the plant is up and shell is available.
        if self.shell is None or not self.topo.is_leaf(ns):
            return ""
        out = self.shell.netns_capture(
            ns.ns_id, ["ip", "-6", "-o", "addr", "show", "dev", "eth0", "scope", "global"])
        for token in out.split():
            if ":" in token and "/" in token:
                return token.split("/")[0]
        return ""

    # ---- ASCII ---------------------------------------------------------------

    def ascii_tree(self) -> str:
        lines = ["Cake Plant topology", ""]

        def walk(ns, indent):
            leased = self._leased(ns)
            tag = f"  [{leased}]" if leased else ""
            lines.append(f"{indent}{ns.ns_id}  ({self._prefix_str(ns)})  {ns.zone}{tag}")
            for child in self.topo.children(ns):
                wire = f"{indent}   |  wire {child.transit}/64  "
                p_if, c_if = self.topo.pair_names(ns, child)
                lines.append(f"{wire}{ns.ns_id}:{p_if} <-> {child.ns_id}:{c_if}")
                walk(child, indent + "   ")

        walk(self.topo.root, "")
        return "\n".join(lines)

    # ---- Mermaid -------------------------------------------------------------

    def mermaid(self) -> str:
        def nid(ns_id):
            return ns_id.replace("-", "_")

        lines = ["graph TD"]
        for a_ns in self.topo.namespaces:
            leased = self._leased(a_ns)
            extra = f"<br/>{leased}" if leased else ""
            label = f"<b>{a_ns.ns_id}</b><br/>{a_ns.zone}<br/>{self._prefix_str(a_ns)}{extra}"
            lines.append(f'  {nid(a_ns.ns_id)}["{label}"]')
        for a_wire in self.topo.wires():
            edge = f"{a_wire.transit}/64<br/>{a_wire.parent_if} ↔ {a_wire.child_if}"
            lines.append(f'  {nid(a_wire.parent.ns_id)} -->|"{edge}"| {nid(a_wire.child.ns_id)}')
        return "\n".join(lines)

    # ---- render --------------------------------------------------------------

    def render(self, write:bool=True) -> Path:
        tree = self.ascii_tree()
        print("\n" + tree + "\n")
        mmd = self.mermaid()
        out = self.output_dir / "build-topology.mmd"
        if write:
            out.write_text(mmd + "\n")
            print(f"Mermaid diagram written to {out}")
        return out
