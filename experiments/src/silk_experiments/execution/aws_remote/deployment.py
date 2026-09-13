from __future__ import annotations

import json
import shlex
import time
import uuid

from ...planning import SmokePlan
from ...registry import BeaconExecutor
from ..inventory import Host
from .connection import CANCELLED, connect, retry_transport, run, run_dir
from .constants import AWS_NODE_PORT


def deploy(plan: SmokePlan, host: Host, node: int) -> None:
    remote_root = run_dir(host, plan.run_id)
    token = uuid.uuid4().hex
    # Replays of this deployment invocation may continue their own directory;
    # a different invocation can never adopt an existing run or launch it twice.
    claim = (
        "import pathlib,sys; p=pathlib.Path(sys.argv[1]); token=sys.argv[2]; "
        "marker=p/'.deployment-token'; "
        "exists=p.exists(); "
        "assert not exists or (marker.is_file() and marker.read_text()==token), 'run exists'; "
        "p.mkdir(parents=True,exist_ok=True); marker.write_text(token); "
        "(p/'state').mkdir(exist_ok=True); (p/'results').mkdir(exist_ok=True)"
    )

    @retry_transport
    def prepare():
        with connect(host) as connection:
            run(connection, ["python3", "-c", claim, remote_root, token])

    prepare()
    _deploy_files(plan, host, node)


DEPLOY_PROBE = r"""
import hashlib,json,pathlib,sys
root,cache=map(pathlib.Path,sys.argv[1:3])
assert not any((root/name).exists() for name in ['node.pid','node.exit','.launch-claimed'])
cache.parent.mkdir(parents=True,exist_ok=True,mode=0o750)
print(json.dumps(cache.is_file() and hashlib.sha256(cache.read_bytes()).hexdigest()==cache.name))
"""

DEPLOY_COMMIT = r"""
import hashlib,json,os,pathlib,subprocess,sys
root,cache=map(pathlib.Path,sys.argv[1:3])
expected=json.loads(sys.argv[3])
assert not any((root/name).exists() for name in ['node.pid','node.exit','.launch-claimed'])
partial=cache.with_name(cache.name+'.partial')
if partial.exists():
    assert hashlib.sha256(partial.read_bytes()).hexdigest()==cache.name, 'binary checksum mismatch'
    partial.chmod(0o555); partial.replace(cache)
assert hashlib.sha256(cache.read_bytes()).hexdigest()==cache.name, 'cached binary checksum mismatch'
binary=root/'experiment-runner'
if binary.exists(): binary.unlink()
os.link(cache,binary)
definition=root/'experiment.toml'
digest=hashlib.sha256(definition.with_suffix('.partial').read_bytes()).hexdigest()
assert digest==sys.argv[4], 'definition checksum mismatch'
definition.with_suffix('.partial').replace(definition)
actual=json.loads(subprocess.check_output([str(binary),'build-info'],text=True,timeout=10))
assert actual==expected, 'runner source identity differs from plan'
(root/'node-id').write_text(sys.argv[5]+'\n')
"""


@retry_transport
def _deploy_files(plan: SmokePlan, host: Host, node: int) -> None:
    remote_root = run_dir(host, plan.run_id)
    cached = f"{host.data_dir}/.binary-cache/{plan.binary_sha256}"
    expected = dict(
        schema_id="silk-build-info/v1",
        git_commit=plan.git_commit,
        git_dirty=plan.git_dirty,
        source_fingerprint=plan.source_fingerprint,
    )
    with connect(host) as connection:
        present = json.loads(
            run(connection, ["python3", "-c", DEPLOY_PROBE, remote_root, cached]).stdout
        )
        connection.sftp().get_channel().settimeout(45)
        if not present:
            connection.put(plan.binary_path, remote=cached + ".partial")
        connection.put(plan.definition_path, remote=f"{remote_root}/experiment.partial")
        run(
            connection,
            [
                "python3",
                "-c",
                DEPLOY_COMMIT,
                remote_root,
                cached,
                json.dumps(expected),
                plan.definition_sha256,
                str(node),
            ],
        )


def launch(
    plan: SmokePlan,
    host: Host,
    node: int,
    endpoints: dict[int, str],
    node_port: int = AWS_NODE_PORT,
) -> None:
    endpoint_json = json.dumps(
        {str(node_id): endpoint for node_id, endpoint in endpoints.items()},
        separators=(",", ":"),
        sort_keys=True,
    )
    command = [
        "./experiment-runner",
        "distributed-run",
        "--config",
        "experiment.toml",
        "--run-id",
        plan.run_id,
        "--node-id",
        str(node),
        "--implementation",
        plan.implementation,
        "--n",
        str(plan.n),
        "--t",
        str(plan.t),
        "--slots",
        str(plan.batch_size),
        "--listen",
        f"0.0.0.0:{node_port}",
        "--store-root",
        "state",
        "--output",
        "results",
        "--samples",
        str(plan.samples),
        "--seed",
        str(plan.seed),
    ]
    environment = {
        "SILK_NODE_ENDPOINTS_JSON": endpoint_json,
        "SILK_SAMPLE_ROLE": plan.sample_role,
        "SILK_EXECUTOR": plan.executor,
        "SILK_NETWORK_SCENARIO": BeaconExecutor.AWS_REMOTE.network_scenario,
        "SILK_RESOURCE_PROFILE": BeaconExecutor.AWS_REMOTE.resource_profile,
    }
    launch_process(host, plan.run_id, command, environment, node)


def launch_process(
    host: Host, run_id: str, command: list[str], environment: dict[str, str], node: int = 0
) -> None:
    """Shared idempotent process launch for Matrix A and B."""
    remote_root = run_dir(host, run_id)
    environment_text = " ".join(
        f"{key}={shlex.quote(value)}" for key, value in sorted(environment.items())
    )
    process = (
        f"cd {shlex.quote(remote_root)} || exit 72; "
        "mkdir .launch-claimed 2>/dev/null || exit 0; "
        "exec > node.log 2>&1; set +e; "
        f"{environment_text} {shlex.join(command)} & child=$!; "
        "printf '%s\\n' \"$child\" > node.pid; "
        'wait "$child"; status=$?; '
        'printf \'%s\\n\' "$status" > node.exit; exit "$status"'
    )
    launcher = f"nohup sh -c {shlex.quote(process)} > /dev/null 2>&1 < /dev/null &"

    @retry_transport
    def start_or_reconcile():
        with connect(host) as connection:
            # A lost SSH reply does not mean the remote launch failed. Check
            # the durable PID first; an atomic remote claim also guards the
            # interval before a delayed launcher has published that PID.
            status = ["test", "-s", f"{remote_root}/node.pid"]
            if run(connection, status, check=False).ok:
                return
            connection.run(launcher, hide=True, warn=False, in_stream=False, timeout=30)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if run(connection, status, check=False).ok:
                    return
                time.sleep(0.25)
            raise RuntimeError(f"node {node} launch has no durable PID; refusing duplicate process")

    start_or_reconcile()


WAIT_SCRIPT = r"""
import pathlib,sys,time
path=pathlib.Path(sys.argv[1]); deadline=time.monotonic()+float(sys.argv[2])
while True:
    if path.is_file():
        value=path.read_text().strip()
        if value.lstrip('-').isdigit():
            print(value); break
        if value: raise RuntimeError('invalid remote exit marker')
    if time.monotonic()>=deadline:
        print('__PENDING__'); break
    time.sleep(.25)
"""


@retry_transport
def wait(plan: SmokePlan, host: Host, node: int, deadline: float) -> int:
    # Long polling happens remotely. Reconnects retain the original controller deadline.
    exit_file = f"{run_dir(host, plan.run_id)}/node.exit"
    with connect(host) as connection:
        while not CANCELLED.is_set() and (remaining := deadline - time.monotonic()) > 0:
            value = run(
                connection, ["python3", "-c", WAIT_SCRIPT, exit_file, str(min(20, remaining))]
            ).stdout.strip()
            if value != "__PENDING__":
                if not value.lstrip("-").isdigit():
                    raise RuntimeError(f"node {node} wrote invalid exit status {value!r}")
                return int(value)
    return 124


@retry_transport
def stop(plan: SmokePlan, host: Host, node: int) -> None:
    remote_root = run_dir(host, plan.run_id)
    pid_file = f"{remote_root}/node.pid"
    exit_file = f"{remote_root}/node.exit"
    with connect(host) as connection:
        script = (
            f"if test -f {shlex.quote(exit_file)}; then exit 0; fi; "
            f"if test -f {shlex.quote(pid_file)}; then "
            f"pid=$(cat {shlex.quote(pid_file)}); "
            "case \"$pid\" in (*[!0-9]*|'') exit 64;; esac; "
            'if ! kill -0 "$pid" 2>/dev/null; then exit 0; fi; '
            'cwd=$(readlink -f "/proc/$pid/cwd" 2>/dev/null || true); '
            f'if test "$cwd" != {shlex.quote(remote_root)}; then exit 65; fi; '
            'kill "$pid" 2>/dev/null || true; '
            'i=0; while kill -0 "$pid" 2>/dev/null && test "$i" -lt 50; do '
            "sleep 0.1; i=$((i + 1)); done; "
            'if kill -0 "$pid" 2>/dev/null; then kill -KILL "$pid" 2>/dev/null || true; fi; '
            'i=0; while kill -0 "$pid" 2>/dev/null && test "$i" -lt 20; do '
            "sleep 0.1; i=$((i + 1)); done; "
            'if kill -0 "$pid" 2>/dev/null; then exit 70; fi; '
            "fi"
        )
        result = connection.run(script, hide=True, warn=True, in_stream=False, timeout=30)
        if not result.ok:
            raise RuntimeError(f"failed to stop node {node} on {host.alias}")
