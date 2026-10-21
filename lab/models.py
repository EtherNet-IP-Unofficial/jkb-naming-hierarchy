"""Plain data records shared across the lab modules."""

from dataclasses import dataclass
from pathlib import Path
from subprocess import Popen


@dataclass
class Daemon():
    """A launched service process plus its merged stdout/stderr log."""

    label:str
    proc:Popen
    log_path:Path
    log_fp:object


@dataclass
class Namespace():

    ns_id:str
    zone:str
    description:str
    tier:int
    """Subnet value, the partitioned DHCPv6-PD byte."""
    subnet:int|None
    """Parent namespace ns_id, or None for the /48 root."""
    parent:str|None = None
    """Transit /64 for the veth wire up to the parent (ends with '::')."""
    transit:str|None = None


@dataclass
class Wire():
    """One veth cable between a parent and child namespace."""

    parent:Namespace
    child:Namespace
    parent_if:str
    child_if:str
    transit:str
