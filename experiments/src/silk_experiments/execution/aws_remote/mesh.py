from __future__ import annotations

import json
import shlex
import time
import uuid
from pathlib import Path

from invoke import UnexpectedExit

from ..inventory import Host
from .connection import connect, parallel_map, retry_transport
from .lifecycle import ensure_idle

SERVER = r"""
import asyncio,sys
identity=sys.argv[1]
async def echo(reader,writer):
    try:
        nonce=await asyncio.wait_for(reader.readline(),5)
        writer.write(identity.encode()+b' '+nonce)
        await writer.drain()
    finally:
        writer.close()
async def main():
    server=await asyncio.start_server(echo,'0.0.0.0',9000,backlog=256)
    async with server: await server.serve_forever()
asyncio.run(main())
"""


def probe_launcher(host: Host) -> str:
    script = shlex.join(["python3", "-u", "-c", SERVER, host.instance_id])
    root = shlex.quote(host.data_dir)
    child = f"cd {root} && printf '%s\\n' \"$$\" > mesh.pid && exec {script}"
    # Redirect the whole background job. Backgrounding `cd ... && nohup ...`
    # leaves the AND-list shell holding the SSH channel until the server exits.
    return (
        f"nohup sh -c {shlex.quote(child)} > "
        f"{shlex.quote(host.data_dir + '/mesh.log')} 2>&1 < /dev/null &"
    )


PROBE_READY = r"""
import socket,sys,time
deadline=time.monotonic()+5
while True:
    try:
        with socket.create_connection(('127.0.0.1',9000),timeout=1) as peer:
            peer.sendall(b'ready\n')
            assert peer.recv(1024).decode().strip()==sys.argv[1]+' ready'
        break
    except (OSError,AssertionError):
        if time.monotonic()>=deadline: raise
        time.sleep(.05)
"""
PROBE_PRESENT = r"""
import socket,sys
try:
    peer=socket.create_connection(('127.0.0.1',9000),timeout=1)
except ConnectionRefusedError:
    raise SystemExit(3)
with peer:
    peer.settimeout(1)
    peer.sendall(b'ready\n')
    if peer.recv(1024).decode().strip()!=sys.argv[1]+' ready': raise SystemExit(4)
"""
CLIENT = r"""
import asyncio,json,sys
targets=json.loads(sys.argv[1]); nonce=sys.argv[2]
async def main():
    sem=asyncio.Semaphore(8)
    async def probe(target):
        identity,address=target
        async with sem:
            writer=None
            try:
                reader,writer=await asyncio.wait_for(asyncio.open_connection(address,9000),3)
                writer.write((nonce+'\n').encode()); await writer.drain()
                value=(await asyncio.wait_for(reader.readline(),3)).decode().strip()
                return identity, value==identity+' '+nonce
            except Exception: return identity,False
            finally:
                if writer: writer.close()
    print(json.dumps(dict(await asyncio.gather(*(probe(t) for t in targets)))))
asyncio.run(main())
"""


def select_compatible(
    hosts: list[Host],
    edges: dict[str, dict[str, bool]],
    required: dict[str, int],
    regions: list[str],
) -> list[Host]:
    """Remove faulty candidates while preserving each region's exact target."""
    pool = list(hosts)
    while True:
        bad = {
            h.instance_id: sum(
                not edges.get(h.instance_id, {}).get(p.instance_id, False)
                or not edges.get(p.instance_id, {}).get(h.instance_id, False)
                for p in pool
                if p != h
            )
            for h in pool
        }
        if not any(bad.values()):
            break
        removable = [
            h
            for h in pool
            if bad[h.instance_id]
            and sum(p.region == h.region for p in pool) > required.get(h.region, 0)
        ]
        if not removable:
            raise RuntimeError("P2P mesh cannot satisfy fixed regional allocation")
        worst = max(removable, key=lambda h: (bad[h.instance_id], h.instance_id))
        pool.remove(worst)
    by_region = {
        r: sorted([h for h in pool if h.region == r], key=lambda h: h.instance_id)[
            : required.get(r, 0)
        ]
        for r in regions
    }
    if any(len(by_region[r]) != required.get(r, 0) for r in regions):
        raise RuntimeError("not enough compatible candidates in region")
    return [
        by_region[r][slot]
        for slot in range(max(required.values()))
        for r in regions
        if slot < len(by_region[r])
    ]


@retry_transport
def ensure_probe_server(host: Host) -> None:
    with connect(host) as connection:
        present = connection.run(
            shlex.join(["python3", "-c", PROBE_PRESENT, host.instance_id]),
            hide=True,
            warn=True,
            in_stream=False,
            timeout=5,
        )
        if present.exited == 0:
            return
        if present.exited != 3:
            raise UnexpectedExit(present)
        # A lost launch acknowledgement is reconciled by the identity probe on
        # retry. An already running matching listener is never launched twice.
        connection.run(probe_launcher(host), hide=True, in_stream=False, timeout=30)
        connection.run(
            shlex.join(["python3", "-c", PROBE_READY, host.instance_id]),
            hide=True,
            in_stream=False,
            timeout=10,
        )


def qualify_mesh(
    hosts: list[Host], required: dict[str, int], regions: list[str], output: Path
) -> list[Host]:
    placement = dict(enumerate(hosts))

    def isolate(_i, host):
        try:
            ensure_idle(host, 9000)
            return True
        except Exception as error:
            print(
                json.dumps(
                    dict(
                        event="mesh-candidate-unavailable",
                        region=host.region,
                        error=type(error).__name__,
                    )
                ),
                flush=True,
            )
            return False

    isolated = parallel_map("pre-probe isolation", placement, isolate)
    hosts = [host for i, host in placement.items() if isolated[i]]
    placement = dict(enumerate(hosts))

    def launch(_i: int, host: Host) -> bool:
        try:
            ensure_probe_server(host)
            return True
        except Exception:
            return False

    all_passes = []
    control_errors = []
    try:
        launched = parallel_map("probe servers", placement, launch)
        hosts = [host for i, host in placement.items() if launched[i]]
        placement = dict(enumerate(hosts))
        for _pass in range(2):
            nonce = uuid.uuid4().hex

            @retry_transport
            def probe(_i: int, host: Host, nonce: str = nonce) -> dict[str, bool]:
                targets = [(h.instance_id, h.endpoint_address) for h in hosts if h != host]
                with connect(host) as connection:
                    result = connection.run(
                        shlex.join(["python3", "-c", CLIENT, json.dumps(targets), nonce]),
                        hide=True,
                        in_stream=False,
                        timeout=150,
                    )
                return json.loads(result.stdout)

            def safe_probe(i, host):
                try:
                    return probe(i, host), None
                except Exception as probe_error:
                    return None, type(probe_error).__name__

            results = {}
            for sweep in range(3):
                pending = {i: h for i, h in placement.items() if i not in results}
                if not pending:
                    break
                if sweep:
                    time.sleep(20)
                observed = parallel_map("directed mesh", pending, safe_probe, max_workers=8)
                for i, (row, error) in observed.items():
                    if row is not None:
                        results[i] = row
                    else:
                        control_errors.append(
                            dict(pass_id=_pass, sweep=sweep, node=hosts[i].instance_id, error=error)
                        )
                output.with_name(output.stem + "-control-errors.private.json").write_text(
                    json.dumps(control_errors, indent=2), encoding="utf-8"
                )
            for i in placement:
                results.setdefault(i, {})
            all_passes.append({hosts[i].instance_id: row for i, row in results.items()})
        output.write_text(json.dumps(all_passes, indent=2) + "\n", encoding="utf-8")
        edges = {
            h.instance_id: {
                p.instance_id: all(
                    rows[h.instance_id].get(p.instance_id, False) for rows in all_passes
                )
                for p in hosts
                if p != h
            }
            for h in hosts
        }
        return select_compatible(hosts, edges, required, regions)
    finally:
        parallel_map("post-probe isolation", placement, isolate)
