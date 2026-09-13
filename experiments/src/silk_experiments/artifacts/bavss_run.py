from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from ..execution.types import BavssProcessCapture
from ..planning import BavssSmokePlan
from .bavss_results import derive_bavss_results
from .common import write_json_new, write_text_new


@dataclass(frozen=True)
class BavssSmokeResult:
    run_id: str
    run_valid: bool
    raw_run: str
    processed_run: str
    process_exit_code: int


def prepare_bavss_run(plan: BavssSmokePlan) -> None:
    raw_run = Path(plan.raw_run)
    if raw_run.exists():
        raise FileExistsError(f"refusing to overwrite raw run: {raw_run}")
    Path(plan.raw_root).mkdir(parents=True, exist_ok=True)


def finish_bavss_run(
    plan: BavssSmokePlan,
    capture: BavssProcessCapture,
) -> BavssSmokeResult:
    state_run = Path(plan.state_run)
    write_text_new(state_run / "runner.stdout.log", capture.stdout)
    write_text_new(state_run / "runner.stderr.log", capture.stderr)
    if capture.exit_code != 0:
        raise RuntimeError(f"bAVSS smoke failed with exit code {capture.exit_code}")

    derivation = derive_bavss_results(Path(plan.raw_run), Path(plan.processed_run))
    result = BavssSmokeResult(
        run_id=plan.run_id,
        run_valid=derivation.run_valid,
        raw_run=plan.raw_run,
        processed_run=plan.processed_run,
        process_exit_code=capture.exit_code,
    )
    write_json_new(Path(plan.processed_run) / "smoke-execution.json", asdict(result))
    return result
