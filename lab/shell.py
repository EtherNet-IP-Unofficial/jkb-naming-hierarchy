"""Thin wrapper around subprocess with a pluggable privilege provider."""

from pathlib import Path
from subprocess import run, PIPE


class Shell():

    def __init__(self, sudo_provider:str|None="sudo"):
        self.sudo_provider = sudo_provider

    def run(self, cmd:list, sudo:bool=False, cwd:Path|None=None) -> None:
        if sudo:
            cmd = [self.sudo_provider, *cmd]
        run(cmd, cwd=cwd or Path.cwd())

    def capture(self, cmd:list, sudo:bool=False) -> str:
        if sudo:
            cmd = [self.sudo_provider, *cmd]
        return run(cmd, stdout=PIPE, text=True).stdout

    def netns(self, ns_id:str, cmd:list, sudo:bool=True) -> None:
        self.run(["ip", "netns", "exec", ns_id, *cmd], sudo=sudo)

    def netns_capture(self, ns_id:str, cmd:list, sudo:bool=True) -> str:
        return self.capture(["ip", "netns", "exec", ns_id, *cmd], sudo=sudo)
