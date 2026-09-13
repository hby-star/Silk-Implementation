from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from typing import Any

from fabric import task

from silk_experiments.orchestration import run_local_suite, run_remote_suite
from silk_experiments.orchestration.managed_remote import cleanup_managed_remote, run_managed_remote


def _emit(call: Callable[..., object], **arguments: Any) -> None:
    try:
        result = call(**arguments)
    except Exception as error:
        print(f"ERROR: {type(error).__name__}: {error}")
        raise SystemExit(1) from None
    print(json.dumps(asdict(result), indent=2, sort_keys=True))


@task
def local(
    context: object,
    mode: str = "smoke",
    implementation: str = "silk-beacon",
    definition: str = "",
    run_name: str = "",
    collection: str = "",
    image: str = "silk-experiments:latest",
    docker_host: str = "",
    rebuild: bool = True,
    execute: bool = True,
    timeout_seconds: int = 1_800,
) -> None:
    """Run the local Docker smoke or matrix suite."""
    del context
    _emit(
        run_local_suite,
        mode=mode,
        implementation=implementation,
        definition=Path(definition) if definition else None,
        run_name=run_name or None,
        collection=Path(collection) if collection else None,
        image=image,
        docker_host=docker_host or None,
        rebuild=rebuild,
        execute=execute,
        timeout_seconds=int(timeout_seconds),
    )


@task
def remote(
    context: object,
    inventory: str = "",
    mode: str = "",
    implementation: str = "silk-beacon",
    definition: str = "",
    run_name: str = "",
    collection: str = "",
    binary: str = "",
    rebuild: bool = False,
    execute: bool = True,
    timeout_seconds: int = 1_800,
    settings: str = "",
    nodes: str = "7,16,31,61,91,121",
    protocols: str = "silk-beacon,rondo-beacon,spurt-beacon",
    state: str = "",
    source_snapshot: str = "",
    retries: int = 0,
    binary_provenance: str = "",
    completed_collection: str = "",
) -> None:
    """Matrix B: managed AWS with --settings, or existing hosts with --inventory."""
    del context
    if settings:
        if (
            inventory
            or collection
            or (mode and mode != "matrix")
            or implementation != "silk-beacon"
        ):
            raise ValueError(
                "managed Matrix B uses --protocols, not inventory/collection/implementation/smoke"
            )
        _emit(
            run_managed_remote,
            settings=Path(settings),
            nodes=nodes,
            protocols=protocols,
            definition=Path(definition) if definition else None,
            run_name=run_name or None,
            state=Path(state) if state else None,
            binary=Path(binary) if binary else None,
            rebuild=rebuild,
            execute=execute,
            timeout_seconds=int(timeout_seconds),
            source_snapshot=Path(source_snapshot) if source_snapshot else None,
            retries=int(retries),
            binary_provenance=Path(binary_provenance) if binary_provenance else None,
            completed_collection=Path(completed_collection) if completed_collection else None,
        )
        return
    if not inventory:
        raise ValueError("remote requires --settings or --inventory")
    if (
        state
        or source_snapshot
        or retries
        or binary_provenance
        or completed_collection
        or nodes != "7,16,31,61,91,121"
        or protocols != "silk-beacon,rondo-beacon,spurt-beacon"
    ):
        raise ValueError("nodes/protocols/state require managed --settings")
    _emit(
        run_remote_suite,
        inventory=Path(inventory),
        mode=mode or "smoke",
        implementation=implementation,
        definition=Path(definition) if definition else None,
        run_name=run_name or None,
        collection=Path(collection) if collection else None,
        binary=Path(binary) if binary else None,
        rebuild=rebuild,
        execute=execute,
        timeout_seconds=int(timeout_seconds),
    )


@task
def remote_cleanup(context: object, state: str) -> None:
    """Recover evidence and reclaim only the campaign recorded in this managed state."""
    del context
    _emit(cleanup_managed_remote, state=Path(state))
