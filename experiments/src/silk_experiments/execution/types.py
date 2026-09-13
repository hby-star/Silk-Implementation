from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ProcessCapture:
    node_id: int
    exit_code: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class BavssProcessCapture:
    exit_code: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class BeaconProcessWorkspace:
    staged_results: Path
    stores: Path
