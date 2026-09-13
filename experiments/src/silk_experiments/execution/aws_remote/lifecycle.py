"""Run isolation and verified, resumable downloads for dedicated AWS instances."""

from __future__ import annotations

import hashlib
import json
import shlex
import shutil
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any

from ..inventory import Host
from .connection import connect, retry_transport

# Operates only inside the campaign's absolute home directory. Never deletes evidence.
IDLE_SCRIPT = r"""
import json, os, pathlib, signal, subprocess, sys, time
base=pathlib.Path(sys.argv[1]).resolve()
port=int(sys.argv[2])
assert len(base.parts)>=4 and str(base).startswith('/home/ubuntu/silk-')
def owned():
    found=[]
    for p in pathlib.Path('/proc').glob('[0-9]*'):
        if int(p.name)==os.getpid(): continue
        try:
            cwd=(p/'cwd').resolve(strict=True)
            state=(p/'stat').read_text().split(') ')[1][0]
            if (cwd==base or base in cwd.parents) and state!='Z': found.append(int(p.name))
        except (OSError, ValueError): pass
    return found
before=owned()
for sig in [signal.SIGTERM,signal.SIGKILL]:
    for pid in owned():
        try: os.kill(pid,sig)
        except ProcessLookupError: pass
    until=time.monotonic()+5
    while owned() and time.monotonic()<until: time.sleep(.1)
assert not owned(), 'campaign process survived cleanup'
sockets=subprocess.check_output(['ss','-H','-ltn','sport','=',':'+str(port)],text=True)
assert not sockets.strip(), 'P2P port still occupied'
mem=dict(line.split(':',1) for line in pathlib.Path('/proc/meminfo').read_text().splitlines())
flags=pathlib.Path('/proc/cpuinfo').read_text()
assert 'avx2' in flags and 'popcnt' in flags, 'native signature CPU features absent'
assert os.cpu_count()==2, 'not a 2-vCPU instance'
assert 3600*1024 <= int(mem['MemTotal'].split()[0]) <= 4300*1024, 'not a 4-GiB instance'
assert int(mem['SwapTotal'].split()[0])==0, 'unexpected swap'
print(json.dumps({'terminated_pids':before,'port_free':True,'remaining_processes':[],
 'mem_available_kib':int(mem['MemAvailable'].split()[0]),'cpu_count':os.cpu_count(),
 'cpu_stat':pathlib.Path('/proc/stat').read_text().splitlines()[0],
 'observed_at_unix':time.time()}))
"""


@retry_transport
def ensure_idle(host: Host, p2p_port: int) -> dict[str, Any]:
    with connect(host) as connection:
        result = connection.run(
            shlex.join(["python3", "-c", IDLE_SCRIPT, host.data_dir, str(p2p_port)]),
            hide=True,
            in_stream=False,
            timeout=30,
        )
    return json.loads(result.stdout)


BUNDLE_SCRIPT = r"""
import hashlib,json,pathlib,sys,tarfile
root=pathlib.Path(sys.argv[1]); bundle=root.parent/(root.name+'.transfer.tar.gz')
files={}
with tarfile.open(bundle,'w:gz',compresslevel=1) as archive:
    for path in sorted(root.rglob('*')):
        if path.is_symlink(): raise RuntimeError('artifact symlink')
        if path.is_dir(): continue
        if not path.is_file(): raise RuntimeError('non-regular artifact')
        name=path.relative_to(root).as_posix()
        digest=hashlib.sha256()
        with path.open('rb') as source:
            for block in iter(lambda:source.read(1024*1024),b''): digest.update(block)
        files[name]=digest.hexdigest()
        archive.add(path,arcname=name,recursive=False)
print(json.dumps({'files':files,'archive':str(bundle),'sha256':hashlib.sha256(bundle.read_bytes()).hexdigest()}))
"""


def download_tree(connection: Any, remote: str, local: Path) -> None:
    """Transfer a compressed, verified archive; preserve exact artifact bytes."""
    result = connection.run(
        shlex.join(["python3", "-c", BUNDLE_SCRIPT, remote]),
        hide=True,
        in_stream=False,
        timeout=120,
    )
    manifest = json.loads(result.stdout)
    expected_remote = str(
        PurePosixPath(remote).with_name(PurePosixPath(remote).name + ".transfer.tar.gz")
    )
    if manifest["archive"] != expected_remote:
        raise RuntimeError("unexpected archive path")
    local.mkdir(parents=True, exist_ok=True)
    partial = local.with_name(local.name + ".transfer.partial")
    connection.sftp().get_channel().settimeout(120)
    connection.sftp().get(expected_remote, str(partial))
    if file_sha256(partial) != manifest["sha256"]:
        raise RuntimeError("artifact archive checksum mismatch")
    with tarfile.open(partial) as archive:
        members = archive.getmembers()
        names = [m.name for m in members]
        if len(set(names)) != len(names) or set(names) != set(manifest["files"]):
            raise RuntimeError("artifact manifest mismatch")
        for member in members:
            path = PurePosixPath(member.name)
            if (
                not member.isfile()
                or path.is_absolute()
                or ".." in path.parts
                or "\\" in member.name
                or ":" in member.name
            ):
                raise RuntimeError("unsafe remote artifact path")
        for member in members:
            target = local.joinpath(*PurePosixPath(member.name).parts)
            if not target.resolve().is_relative_to(local.resolve()):
                raise RuntimeError("local artifact path escaped output")
            target.parent.mkdir(parents=True, exist_ok=True)
            staging = target.with_name(target.name + ".partial")
            with archive.extractfile(member) as source, staging.open("wb") as output:
                shutil.copyfileobj(source, output)
            if file_sha256(staging) != manifest["files"][member.name]:
                raise RuntimeError("artifact file checksum mismatch")
            staging.replace(target)
    partial.unlink()
    (local / "transfer-sha256.json").write_text(
        json.dumps(manifest["files"], indent=2) + "\n", encoding="utf-8"
    )


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def retry_read(function: Any) -> Any:
    return retry_transport(function)()
