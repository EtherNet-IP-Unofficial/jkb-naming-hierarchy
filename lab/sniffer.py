"""Per-wire packet capture via tcpdump, one pcap per veth cable."""

import shutil
from pathlib import Path
from subprocess import Popen, DEVNULL


class Sniffer():

    def __init__(self, shell, topology, output_dir, run_user:str):
        self.shell = shell
        self.topo = topology
        self.pcap_dir = Path(output_dir) / "pcaps"
        self.run_user = run_user
        self.captures = []

    def start(self):
        # Sniff the child end of each veth: it sees both directions of that link. Start before
        # the daemons so the DHCPv6/PD, RA and DDNS exchanges are captured from the first packet.
        if shutil.which("tcpdump") is None:
            print("Sniffer: tcpdump not found on PATH, skipping capture (install tcpdump to enable).")
            return
        self.pcap_dir.mkdir(parents=True, exist_ok=True)
        for a_wire in self.topo.wires():
            pcap = self.pcap_dir / f"{a_wire.parent.ns_id}--{a_wire.child.ns_id}.pcap"
            # -Z drops privileges to the file owner so tcpdump can write under $HOME.
            cmd = [self.shell.sudo_provider, "ip", "netns", "exec", a_wire.child.ns_id,
                   "tcpdump", "-i", a_wire.child_if, "-U", "-n", "-Z", self.run_user, "-w", str(pcap)]
            proc = Popen(cmd, stdout=DEVNULL, stderr=DEVNULL)
            self.captures.append((f"{a_wire.parent.ns_id}<->{a_wire.child.ns_id}", proc, pcap))
            print(f"Sniffing {a_wire.child.ns_id}:{a_wire.child_if} -> {pcap}")

    def stop(self):
        for _label, proc, _pcap in self.captures:
            proc.terminate()
        for _label, proc, _pcap in self.captures:
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
        self.captures = []
