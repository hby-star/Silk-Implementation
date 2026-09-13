from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path

from .artifacts import derive_bavss_results, derive_beacon_results
from .config import load_definition
from .execution.aws_remote import build_aws_runner
from .execution.docker_simulation import (
    DEFAULT_IMAGE,
    build_image,
    image_id,
)
from .execution.inventory import load_inventory
from .planning import (
    build_bavss_matrix_plans,
    build_bavss_smoke_plan,
    build_beacon_matrix_plans,
    build_beacon_smoke_plan,
    load_bavss_smoke_plan,
    load_smoke_plan,
    save_bavss_smoke_plan,
    save_plan_collection,
    save_smoke_plan,
)
from .registry import BavssExecutor, BeaconExecutor, BeaconImplementation
from .workflows import run_bavss_smoke, run_beacon_smoke


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="silk-exp")
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate-definition")
    validate.add_argument("definition", type=Path)

    derive = commands.add_parser("derive-beacon-results")
    derive.add_argument("--raw-run", required=True, type=Path)
    derive.add_argument("--processed-run", required=True, type=Path)

    derive_bavss = commands.add_parser("derive-bavss-results")
    derive_bavss.add_argument("--raw-run", required=True, type=Path)
    derive_bavss.add_argument("--processed-run", required=True, type=Path)

    plan_smoke = commands.add_parser("plan-beacon-smoke")
    plan_smoke.add_argument("--definition", required=True, type=Path)
    plan_smoke.add_argument("--run-id", required=True)
    plan_smoke.add_argument(
        "--implementation",
        required=True,
        choices=tuple(item.value for item in BeaconImplementation),
    )
    plan_smoke.add_argument("--binary", type=Path)
    plan_smoke.add_argument(
        "--executor",
        choices=tuple(item.value for item in BeaconExecutor),
        default=BeaconExecutor.DOCKER.value,
    )
    plan_smoke.add_argument("--image", default=DEFAULT_IMAGE)
    plan_smoke.add_argument("--docker-host")
    plan_smoke.add_argument("--inventory", type=Path)
    plan_smoke.add_argument("--matrix-n", type=int)
    plan_smoke.add_argument("--outputs-per-run", type=int)

    run_smoke = commands.add_parser("run-beacon-smoke")
    run_smoke.add_argument("--plan", required=True, type=Path)
    run_smoke.add_argument("--timeout-seconds", type=int, default=180)

    build_docker = commands.add_parser("build-docker-image")
    build_docker.add_argument("--image", default=DEFAULT_IMAGE)
    build_docker.add_argument("--docker-host")

    build_aws = commands.add_parser("build-aws-runner")
    build_aws.add_argument("--output", required=True, type=Path)

    validate_inventory = commands.add_parser("validate-inventory")
    validate_inventory.add_argument("--inventory", required=True, type=Path)
    validate_inventory.add_argument("--nodes", required=True, type=int)

    plan_bavss = commands.add_parser("plan-bavss-smoke")
    plan_bavss.add_argument("--definition", required=True, type=Path)
    plan_bavss.add_argument("--run-id", required=True)
    plan_bavss.add_argument("--binary", type=Path)
    plan_bavss.add_argument("--executor", choices=tuple(item.value for item in BavssExecutor))
    plan_bavss.add_argument("--image", default=DEFAULT_IMAGE)
    plan_bavss.add_argument("--docker-host")
    plan_bavss.add_argument("--matrix-n", type=int)
    plan_bavss.add_argument("--inventory", type=Path)

    run_bavss = commands.add_parser("run-bavss-smoke")
    run_bavss.add_argument("--plan", required=True, type=Path)
    run_bavss.add_argument("--timeout-seconds", type=int, default=180)

    plan_beacon_matrix = commands.add_parser("plan-beacon-matrix")
    plan_beacon_matrix.add_argument("--definition", required=True, type=Path)
    plan_beacon_matrix.add_argument("--run-prefix", required=True)
    plan_beacon_matrix.add_argument("--binary", type=Path)
    plan_beacon_matrix.add_argument("--image", default=DEFAULT_IMAGE)
    plan_beacon_matrix.add_argument("--docker-host")
    plan_beacon_matrix.add_argument("--inventory", type=Path)
    plan_beacon_matrix.add_argument("--outputs-per-run", type=int)
    plan_beacon_matrix.add_argument(
        "--implementation",
        choices=tuple(item.value for item in BeaconImplementation),
    )
    plan_beacon_matrix.add_argument("--collection", required=True, type=Path)

    run_beacon_matrix = commands.add_parser("run-beacon-matrix")
    run_beacon_matrix.add_argument("--collection", required=True, type=Path)
    run_beacon_matrix.add_argument("--timeout-seconds", type=int, default=1800)

    plan_bavss_matrix = commands.add_parser("plan-bavss-matrix")
    plan_bavss_matrix.add_argument("--definition", required=True, type=Path)
    plan_bavss_matrix.add_argument("--run-prefix", required=True)
    plan_bavss_matrix.add_argument("--binary", type=Path)
    plan_bavss_matrix.add_argument("--image", default=DEFAULT_IMAGE)
    plan_bavss_matrix.add_argument("--docker-host")
    plan_bavss_matrix.add_argument("--inventory", type=Path)
    plan_bavss_matrix.add_argument("--collection", required=True, type=Path)

    run_bavss_matrix = commands.add_parser("run-bavss-matrix")
    run_bavss_matrix.add_argument("--collection", required=True, type=Path)
    run_bavss_matrix.add_argument("--timeout-seconds", type=int, default=1800)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    if arguments.command == "validate-definition":
        definition = load_definition(arguments.definition)
        print(
            json.dumps(
                {
                    "experiment_id": definition.kind.value,
                    "execution_mode": definition.execution_mode.value,
                    "definition_sha256": definition.sha256,
                    "smoke": asdict(definition.smoke),
                    "matrix": asdict(definition.matrix),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if arguments.command == "derive-beacon-results":
        derivation = derive_beacon_results(arguments.raw_run, arguments.processed_run)
        print(json.dumps(asdict(derivation), indent=2, sort_keys=True))
        return 0 if derivation.run_valid else 2
    if arguments.command == "derive-bavss-results":
        bavss_derivation = derive_bavss_results(arguments.raw_run, arguments.processed_run)
        print(json.dumps(asdict(bavss_derivation), indent=2, sort_keys=True))
        return 0 if bavss_derivation.run_valid else 2
    if arguments.command == "plan-beacon-smoke":
        planned_docker_image = (
            arguments.image if arguments.executor == BeaconExecutor.DOCKER.value else None
        )
        planned_docker_host = (
            arguments.docker_host if arguments.executor == BeaconExecutor.DOCKER.value else None
        )
        plan = build_beacon_smoke_plan(
            arguments.definition,
            arguments.run_id,
            arguments.implementation,
            arguments.binary,
            arguments.executor,
            planned_docker_image,
            image_id(planned_docker_image, planned_docker_host)
            if planned_docker_image is not None
            else None,
            planned_docker_host,
            arguments.matrix_n,
            arguments.outputs_per_run,
            arguments.inventory,
        )
        path = save_smoke_plan(plan)
        print(json.dumps({"plan": asdict(plan), "plan_path": str(path)}, indent=2, sort_keys=True))
        return 0
    if arguments.command == "run-beacon-smoke":
        if arguments.timeout_seconds <= 0:
            raise ValueError("--timeout-seconds must be positive")
        smoke_result = run_beacon_smoke(
            load_smoke_plan(arguments.plan),
            timeout_seconds=arguments.timeout_seconds,
        )
        print(json.dumps(asdict(smoke_result), indent=2, sort_keys=True))
        return 0 if smoke_result.run_valid else 2
    if arguments.command == "build-docker-image":
        print(
            json.dumps(
                {
                    "image": arguments.image,
                    "docker_host": arguments.docker_host,
                    "image_id": build_image(arguments.image, arguments.docker_host),
                }
            )
        )
        return 0
    if arguments.command == "build-aws-runner":
        artifact = build_aws_runner(arguments.output)
        print(json.dumps(asdict(artifact), indent=2, sort_keys=True))
        return 0
    if arguments.command == "validate-inventory":
        if arguments.nodes <= 0:
            raise ValueError("--nodes must be positive")
        inventory = load_inventory(arguments.inventory)
        placement = inventory.replica_placement(arguments.nodes)
        print(
            json.dumps(
                {
                    "executor": BeaconExecutor.AWS_REMOTE.value,
                    "inventory_path": str(inventory.path),
                    "inventory_sha256": inventory.sha256,
                    "p2p_port": inventory.p2p_port,
                    "node_count": arguments.nodes,
                    "one_instance_per_node": True,
                    "placement": [
                        {
                            "node_id": node,
                            "host_alias": placement[node].alias,
                            "region": placement[node].region,
                            "instance_id": placement[node].instance_id,
                        }
                        for node in range(arguments.nodes)
                    ],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if arguments.command == "plan-bavss-smoke":
        bavss_definition = load_definition(arguments.definition)
        bavss_executor = arguments.executor or bavss_definition.executors[0]
        bavss_docker = bavss_executor == BavssExecutor.DOCKER_AGGREGATE.value
        bavss_docker_host = arguments.docker_host if bavss_docker else None
        bavss_plan = build_bavss_smoke_plan(
            arguments.definition,
            arguments.run_id,
            arguments.binary,
            bavss_executor,
            arguments.image if bavss_docker else None,
            image_id(arguments.image, bavss_docker_host) if bavss_docker else None,
            bavss_docker_host,
            arguments.matrix_n,
            inventory_path=arguments.inventory,
        )
        path = save_bavss_smoke_plan(bavss_plan)
        print(
            json.dumps(
                {"plan": asdict(bavss_plan), "plan_path": str(path)},
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if arguments.command == "run-bavss-smoke":
        if arguments.timeout_seconds <= 0:
            raise ValueError("--timeout-seconds must be positive")
        bavss_result = run_bavss_smoke(
            load_bavss_smoke_plan(arguments.plan),
            timeout_seconds=arguments.timeout_seconds,
        )
        print(json.dumps(asdict(bavss_result), indent=2, sort_keys=True))
        return 0 if bavss_result.run_valid else 2
    if arguments.command == "plan-beacon-matrix":
        matrix_definition = load_definition(arguments.definition)
        matrix_uses_docker = BeaconExecutor.DOCKER.value in matrix_definition.matrix.executors
        matrix_image_id = (
            image_id(arguments.image, arguments.docker_host) if matrix_uses_docker else None
        )
        beacon_matrix_plans = build_beacon_matrix_plans(
            arguments.definition,
            arguments.run_prefix,
            arguments.binary,
            arguments.image if matrix_uses_docker else None,
            matrix_image_id,
            arguments.docker_host,
            arguments.outputs_per_run,
            arguments.implementation,
            arguments.inventory,
        )
        paths = [save_smoke_plan(plan) for plan in beacon_matrix_plans]
        collection = save_plan_collection(arguments.collection, beacon_matrix_plans)
        print(
            json.dumps(
                {
                    "collection": str(collection),
                    "plan_count": len(beacon_matrix_plans),
                    "plan_paths": [str(path) for path in paths],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if arguments.command == "run-beacon-matrix":
        if arguments.timeout_seconds <= 0:
            raise ValueError("--timeout-seconds must be positive")
        beacon_collection_plans = _collection_plans(
            arguments.collection,
            "beacon-performance",
        )
        beacon_results = [
            run_beacon_smoke(
                load_smoke_plan(Path(str(plan["state_run"])) / "plan.json"),
                timeout_seconds=arguments.timeout_seconds,
            )
            for plan in beacon_collection_plans
        ]
        print(json.dumps([asdict(result) for result in beacon_results], indent=2, sort_keys=True))
        return 0 if all(result.run_valid for result in beacon_results) else 2
    if arguments.command == "plan-bavss-matrix":
        bavss_definition = load_definition(arguments.definition)
        bavss_docker = bavss_definition.matrix.executors == (BavssExecutor.DOCKER_AGGREGATE.value,)
        bavss_docker_host = arguments.docker_host if bavss_docker else None
        bavss_matrix_plans = build_bavss_matrix_plans(
            arguments.definition,
            arguments.run_prefix,
            arguments.binary,
            arguments.image if bavss_docker else None,
            image_id(arguments.image, bavss_docker_host) if bavss_docker else None,
            bavss_docker_host,
            inventory_path=arguments.inventory,
        )
        paths = [save_bavss_smoke_plan(plan) for plan in bavss_matrix_plans]
        collection = save_plan_collection(arguments.collection, bavss_matrix_plans)
        print(
            json.dumps(
                {
                    "collection": str(collection),
                    "plan_count": len(bavss_matrix_plans),
                    "plan_paths": [str(path) for path in paths],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if arguments.command == "run-bavss-matrix":
        if arguments.timeout_seconds <= 0:
            raise ValueError("--timeout-seconds must be positive")
        bavss_collection_plans = _collection_plans(
            arguments.collection,
            "bavss-phase-cost",
        )
        bavss_results = [
            run_bavss_smoke(
                load_bavss_smoke_plan(Path(str(plan["state_run"])) / "plan.json"),
                timeout_seconds=arguments.timeout_seconds,
            )
            for plan in bavss_collection_plans
        ]
        print(json.dumps([asdict(result) for result in bavss_results], indent=2, sort_keys=True))
        return 0 if all(result.run_valid for result in bavss_results) else 2
    raise AssertionError(f"unhandled command {arguments.command}")


def _collection_plans(path: Path, experiment_id: str) -> list[dict[str, object]]:
    value = json.loads(path.resolve().read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_id") != "silk-plan-collection/v1":
        raise ValueError("unsupported plan collection")
    plans = value.get("plans")
    if not isinstance(plans, list) or not plans:
        raise ValueError("plan collection is empty")
    if any(
        not isinstance(plan, dict) or plan.get("experiment_id") != experiment_id for plan in plans
    ):
        raise ValueError("plan collection contains the wrong experiment")
    return plans


if __name__ == "__main__":
    raise SystemExit(main())
