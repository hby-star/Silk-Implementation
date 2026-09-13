from __future__ import annotations

import json
import shlex
import time
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor
from concurrent.futures import wait as futures_wait
from contextlib import contextmanager
from functools import wraps
from pathlib import PurePosixPath
from threading import BoundedSemaphore, Event, Lock, RLock
from typing import Any, TypeVar

from fabric import Connection
from invoke import CommandTimedOut, UnexpectedExit
from paramiko import AuthenticationException, BadHostKeyException, SSHException, Transport

from ..inventory import Host
from .constants import SSH_KEEPALIVE_SECONDS

T = TypeVar("T")
SSH_HANDSHAKES = BoundedSemaphore(16)
_GATEWAY_LOCK = Lock()
_GATEWAYS: dict[Host, Connection] = {}
_POOL_LOCK = Lock()
_POOL: dict[Host, object] = {}
_POOL_ENABLED = False
CANCELLED = Event()


class _GatewayConnection(Connection):
    """Fabric omits a timeout on direct-tcpip channel creation by default."""

    def open_gateway(self):
        self.gateway.open()
        return self.gateway.transport.open_channel(
            kind="direct-tcpip",
            dest_addr=(self.host, int(self.port)),
            src_addr=("", 0),
            timeout=15,
        )


class _BoundedSendSocket:
    """Stop Paramiko's otherwise unlimited retry of timed-out socket writes."""

    def __init__(self, sock):
        self.sock = sock

    def __getattr__(self, name):
        return getattr(self.sock, name)

    def send(self, data):
        deadline = time.monotonic() + 45
        while True:
            try:
                return self.sock.send(data)
            except TimeoutError as error:
                if time.monotonic() >= deadline:
                    # Packetizer retries socket.timeout forever; a connection
                    # error instead closes the transport and reaches our retry.
                    raise ConnectionResetError("SSH send made no progress for 45s") from error


def _bounded_transport(sock, **kwargs):
    # Transport sets a short socket timeout. Apply at both the direct socket
    # and gateway channel, so a blocked gateway cannot pin every upload worker.
    return Transport(_BoundedSendSocket(sock), **kwargs)


class _Lease:
    def __init__(self, host):
        self.host = host
        self.lock = RLock()
        self.connection = None

    def __enter__(self):
        self.lock.acquire()
        try:
            if self.connection is None or not self.connection.is_connected:
                if self.connection is not None:
                    self.connection.close()
                self.connection = connect_once(self.host)
            return self.connection
        except BaseException:
            self.lock.release()
            raise

    def __exit__(self, kind, value, traceback):
        try:
            if kind is not None:
                self.connection.close()
                self.connection = None
        finally:
            self.lock.release()


@contextmanager
def pooled_connections():
    """Campaign-owned pool; one serialized authenticated connection per host."""
    global _POOL_ENABLED
    previous = _POOL_ENABLED
    _POOL_ENABLED = True
    if not previous:
        CANCELLED.clear()
    try:
        yield
    finally:
        _POOL_ENABLED = previous
        if not previous:
            close_gateways()


def retry_transport(function):
    """Retry only explicitly idempotent operations after a dropped SSH transport."""

    @wraps(function)
    def retried(*args, **kwargs):
        for attempt in range(3):
            try:
                return function(*args, **kwargs)
            except (AuthenticationException, BadHostKeyException):
                raise
            except UnexpectedExit as error:
                # Paramiko uses -1 when no exit status arrives. The decorated
                # operations are explicitly idempotent; genuine remote failure
                # statuses must still stop immediately. Protocol launch is not
                # decorated and is never blindly replayed.
                if error.result.exited != -1 or attempt == 2:
                    raise
                time.sleep((2, 5)[attempt])
            except (EOFError, OSError, SSHException, CommandTimedOut):
                if attempt == 2:
                    raise
                time.sleep((2, 5)[attempt])

    return retried


def connect_once(host: Host, *, connect_timeout: int = 10) -> Connection:
    connect_kwargs = (
        {
            "key_filename": host.identity_file,
            "allow_agent": False,
            "look_for_keys": False,
            "banner_timeout": 15,
            "auth_timeout": 15,
            "channel_timeout": 15,
        }
        if host.identity_file
        else {"banner_timeout": 15, "auth_timeout": 15, "channel_timeout": 15}
    )
    connect_kwargs["transport_factory"] = _bounded_transport
    connection_type = _GatewayConnection if host.ssh_gateway else Connection
    connection = connection_type(
        host.address,
        user=host.user or None,
        port=host.port,
        connect_timeout=connect_timeout,
        connect_kwargs=connect_kwargs,
        gateway=_gateway_connection(host.ssh_gateway) if host.ssh_gateway else None,
        forward_agent=False,
    )
    try:
        with SSH_HANDSHAKES:
            connection.open()
    except Exception:
        connection.close()
        raise
    if connection.transport is not None:
        connection.transport.set_keepalive(SSH_KEEPALIVE_SECONDS)
    return connection


@retry_transport
def connect(host: Host):
    if _POOL_ENABLED:
        with _POOL_LOCK:
            return _POOL.setdefault(host, _Lease(host))
    return connect_once(host)


def _gateway_connection(host: Host) -> Connection:
    if host.ssh_gateway:
        raise ValueError("nested SSH gateways are unsupported")
    # One authenticated transport multiplexes direct-tcpip channels. Keys and
    # target authentication stay local; no key or agent is forwarded to EC2.
    with _GATEWAY_LOCK:
        gateway = _GATEWAYS.get(host)
        if gateway is None or not gateway.is_connected:
            if gateway is not None:
                gateway.close()
            gateway = retry_transport(connect_once)(host)
            _GATEWAYS[host] = gateway
        return gateway


def close_gateways() -> None:
    with _POOL_LOCK:
        leases = list(_POOL.values())
        _POOL.clear()
    for lease in leases:
        with lease.lock:
            if lease.connection is not None:
                lease.connection.close()
                lease.connection = None
    with _GATEWAY_LOCK:
        for gateway in _GATEWAYS.values():
            gateway.close()
        _GATEWAYS.clear()


PREFLIGHT_SCRIPT = r"""
import datetime,json,os,pathlib,platform,urllib.request
mem=dict(line.split(':',1) for line in pathlib.Path('/proc/meminfo').read_text().splitlines())
asset=pathlib.Path('/sys/devices/virtual/dmi/id/board_asset')
identity=asset.read_text().strip() if asset.exists() else ''
if not identity.startswith('i-'):
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    base='http://169.254.169.254/latest/'
    req=urllib.request.Request(base+'api/token',method='PUT',headers={'X-aws-ec2-metadata-token-ttl-seconds':'60'})
    token=opener.open(req,timeout=5).read().decode()
    req=urllib.request.Request(base+'meta-data/instance-id',headers={'X-aws-ec2-metadata-token':token})
    identity=opener.open(req,timeout=5).read().decode().strip()
print(json.dumps(dict(system=platform.system(),architecture=platform.machine(),kernel=platform.release(),
    logical_cpus=os.cpu_count(),mem_available_mib=int(mem['MemAvailable'].split()[0])//1024,
    instance_id=identity,observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())))
"""


@retry_transport
def preflight(host: Host, node: int) -> dict[str, object]:
    # One remote request replaces eight commands and their network round trips.
    with connect(host) as connection:
        value = json.loads(run(connection, ["python3", "-c", PREFLIGHT_SCRIPT]).stdout)
    if value["system"] != "Linux" or value["architecture"] not in {"x86_64", "amd64"}:
        raise RuntimeError("incompatible AWS runner host")
    if value["instance_id"] != host.instance_id:
        raise RuntimeError("EC2 identity mismatch")
    if not all(
        type(value[k]) is int and value[k] >= 0 for k in ("logical_cpus", "mem_available_mib")
    ):
        raise RuntimeError("invalid host resource observation")
    return dict(value, node_id=node, host_alias=host.alias, region=host.region)


def parallel_map(
    label: str,
    placement: dict[int, Host],
    function: Callable[[int, Host], T],
    *,
    max_workers: int = 16,
) -> dict[int, T]:
    results: dict[int, T] = {}
    errors: list[tuple[int, Exception]] = []
    print(
        json.dumps(dict(event="remote-stage-start", stage=label, nodes=len(placement))), flush=True
    )
    if not placement:
        return results
    with ThreadPoolExecutor(max_workers=min(max_workers, len(placement))) as pool:
        futures = {pool.submit(function, node, host): node for node, host in placement.items()}
        pending = set(futures)
        try:
            while pending:
                done, pending = futures_wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    node = futures[future]
                    try:
                        results[node] = future.result()
                    except Exception as error:
                        errors.append((node, error))
        except BaseException:
            CANCELLED.set()
            for future in pending:
                future.cancel()
            raise
    if errors:
        failed_node, failure = sorted(errors, key=lambda item: item[0])[0]
        raise RuntimeError(
            f"{label} failed for node {failed_node}: {type(failure).__name__}: {failure}"
        ) from failure
    print(
        json.dumps(dict(event="remote-stage-complete", stage=label, nodes=len(results))), flush=True
    )
    return results


def run(
    connection: Connection,
    command: list[str],
    *,
    check: bool = True,
    stdout_path: str | None = None,
) -> Any:
    shell = shlex.join(command)
    if stdout_path is not None:
        shell = f"{shell} > {shlex.quote(stdout_path)}"
    result = connection.run(shell, hide=True, warn=not check, in_stream=False, timeout=30)
    if check and not result.ok:
        raise RuntimeError(
            f"remote command failed with exit {result.exited}: {result.stderr.strip()}"
        )
    return result


def run_dir(host: Host, run_id: str) -> str:
    return str(PurePosixPath(host.data_dir) / run_id)
