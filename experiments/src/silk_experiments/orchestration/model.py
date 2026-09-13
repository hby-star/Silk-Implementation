from __future__ import annotations

from dataclasses import dataclass

from ..artifacts import BeaconSmokeResult


@dataclass(frozen=True)
class SuiteResult:
    environment: str
    mode: str
    executor: str
    plan_paths: tuple[str, ...]
    collection_path: str | None
    executed: bool
    run_results: tuple[BeaconSmokeResult, ...]

    @property
    def valid(self) -> bool | None:
        if not self.executed:
            return None
        return bool(self.run_results) and all(result.run_valid for result in self.run_results)
