"""Orchestrate the MANUAL.md virtual plant on one Linux box.

This composes the decoupled lab modules:

    shell        - subprocess + privilege wrapper
    topology     - pure namespace/prefix/wire model
    network      - namespaces, veth wires, routes, DAD
    daemons      - launch/monitor/reap service processes
    services     - per-tier config generation + daemon launch
    sniffer      - per-wire tcpdump capture
    verify       - end-to-end expected-vs-actual checks
    visualize    - ASCII tree + Mermaid diagram of the build

It instantiates the manual's flat plan (Plant /48 -> Line /56 -> Machine /64 ->
leaf) as network namespaces wired by veth pairs, generates every daemon config
under output_dir, launches the real services per namespace, sniffs each wire,
and tears everything down again. It installs nothing; these packages must be
present (MANUAL.md Step 0):

    kea-dhcp6-server kea-dhcp-ddns-server bind9 bind9-utils radvd lldpd
    avahi-daemon isc-dhcp-client odhcp6c tcpdump jq iproute2

Run as root (or via a sudo_provider). Throwaway namespaces -- do not point any
of this at a real interface.
"""

import os
import pwd
from pathlib import Path
from time import sleep

from shell import Shell
from deps import DependencyChecker
from topology import Topology
from network import NetworkBuilder
from daemons import DaemonManager
from services import ServiceBuilder
from sniffer import Sniffer
from verify import Verifier
from visualize import Visualizer

SCRIPT_DIR = Path(__file__).resolve().absolute().parent
TEMPLATES_DIR = SCRIPT_DIR / "templates"


class CakePlant():

    def __init__(self,
                 sudo_provider:str|None="sudo",
                 json_config:Path|None=None,
                 output_dir:Path|str|None=None,
                 sniff:bool=True):
        self.output_dir = Path(output_dir) if output_dir else Path.cwd()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._sniff_enabled = sniff
        run_user = pwd.getpwuid(os.getuid()).pw_name

        self.shell = Shell(sudo_provider)
        self.deps = DependencyChecker(self.shell, self.output_dir)
        self.topo = Topology(json_config=json_config)
        self.network = NetworkBuilder(self.shell, self.topo)
        self.daemons = DaemonManager(self.shell, self.output_dir)
        self.services = ServiceBuilder(self.shell, self.topo, self.daemons, self.network,
                                       self.output_dir, TEMPLATES_DIR, run_user)
        self.sniffer = Sniffer(self.shell, self.topo, self.output_dir, run_user)
        self.verifier = Verifier(self.shell, self.topo, self.output_dir)
        self.visualizer = Visualizer(self.topo, self.output_dir, self.shell)

    # ---- rollback bookkeeping ------------------------------------------------

    @property
    def _rollback_file(self) -> Path:
        return self.output_dir / ".rollback.txt"

    def _stage(self, name:str) -> None:
        with open(self._rollback_file, "a") as fp:
            fp.write(f"{name}\n")

    def rollback(self):
        rb = self._rollback_file
        stages = []
        if rb.is_file():
            with open(rb, "r") as fp:
                stages = [ln.strip() for ln in fp.readlines()]
            stages.reverse()

        for stage in stages:
            if stage == "start_services":
                self.daemons.stop()
                self.network.kill_stragglers()
            elif stage == "start_sniff":
                self.sniffer.stop()
            elif stage == "create_wires":
                self.network.destroy_wires()
            elif stage == "register_namespaces":
                self.network.unregister_namespaces()
        if rb.is_file():
            rb.unlink()

    # ---- lifecycle -----------------------------------------------------------

    def build(self):
        # First step: fail fast if any external tool the lab needs is missing.
        self.deps.require()

        self._stage("register_namespaces")
        self.network.register_namespaces()
        self.network.enable_forwarding()

        self._stage("create_wires")
        self.network.create_wires()
        self.network.create_routes()
        # Let DAD finish on every veth link-local before daemons bind to them.
        self.network.wait_all_dad()

        if self._sniff_enabled:
            self._stage("start_sniff")
            self.sniffer.start()

        self._stage("start_services")
        self.daemons.start_monitor()
        self.services.start_all()

    def verify(self):
        return self.verifier.run()

    def visualize(self):
        return self.visualizer.render()


if __name__ == "__main__":

    print("Welcome to our Cake Plant.")
    cp = CakePlant(sudo_provider="sudo")
    cp.rollback()

    try:
        cp.build()
        cp.visualize()
        sleep(10)  # Give the leaves a chance to lease and register DNS.
        cp.verify()
    finally:
        cp.rollback()
