"""Campaign-scoped EC2 provisioning. All resource identities live in a private ledger."""

from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

import yaml
from paramiko import AuthenticationException, BadHostKeyException

from ..inventory import Host
from .connection import close_gateways, connect_once, preflight


class AwsError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


_DIAGNOSTICS_LOCK = threading.Lock()


def _record_api_failure(record: dict[str, Any]) -> None:
    # CLI diagnostics may contain resource identities. Only the scoped private
    # journal receives raw output; progress and exception text remain sanitized.
    path = os.environ.get("SILK_AWS_DIAGNOSTICS_PATH")
    if path:
        try:
            with _DIAGNOSTICS_LOCK:
                target = Path(path)
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(record) + "\n")
        except OSError:
            print(json.dumps({"event": "aws-diagnostic-write-failed"}), flush=True)


def aws(region: str, service: str, operation: str, **parameters: Any) -> Any:
    from botocore.exceptions import BotoCoreError, ClientError

    from .sdk import call

    try:
        return call(region, service, operation, parameters)
    except (BotoCoreError, ClientError) as error:
        code = (
            error.response["Error"]["Code"]
            if isinstance(error, ClientError)
            else type(error).__name__
        )
        _record_api_failure(
            dict(
                timestamp=time.time(),
                region=region,
                service=service,
                operation=operation,
                code=code,
            )
        )
        raise AwsError(code) from error


class Fleet:
    def __init__(
        self,
        settings: Path,
        discovery: Path,
        state: Path,
        campaign: str,
        *,
        capacity_limits: dict[str, int],
    ):
        if not re.fullmatch(r"silk-aws-[a-z0-9-]+", campaign):
            raise ValueError("invalid campaign identity")
        self.settings = yaml.safe_load(settings.read_text(encoding="utf-8"))
        self.regions = self.settings["instances"]["regions"]
        if (
            set(capacity_limits) != set(self.regions)
            or any(type(v) is not int or v < 0 for v in capacity_limits.values())
            or not 0 < sum(capacity_limits.values()) <= 200
        ):
            raise ValueError("invalid explicit fleet budget (maximum 200 candidates)")
        self.capacity_limits = capacity_limits
        self.key = self.settings["key"]
        self.discovery = discovery
        self.state = state.resolve()
        self.state.mkdir(parents=True, exist_ok=True)
        self.path = self.state / "fleet.private.json"
        self.campaign = campaign
        self.lock = threading.RLock()
        self.data = (
            json.loads(self.path.read_text())
            if self.path.exists()
            else {"campaign": campaign, "groups": {}, "launches": [], "instances": []}
        )
        if self.data["campaign"] != campaign:
            raise ValueError("ledger belongs to another campaign")
        self.save()

    def save(self) -> None:
        with self.lock:
            partial = self.path.with_suffix(".partial")
            partial.write_text(json.dumps(self.data, indent=2) + "\n", encoding="utf-8")
            # Windows readers/indexers can briefly deny rename despite the
            # process lock. Keep the old complete ledger until atomic publish
            # succeeds; never truncate it or continue provisioning unrecorded.
            for attempt in range(11):
                try:
                    partial.replace(self.path)
                    break
                except PermissionError:
                    if attempt == 10:
                        raise
                    time.sleep(min(0.05 * 2**attempt, 0.5))

    def tags(self, role: str) -> list[dict[str, str]]:
        return [
            {"Key": "SilkCampaign", "Value": self.campaign},
            {"Key": "Name", "Value": self.campaign},
            {"Key": "Role", "Value": role},
        ]

    def network(self, region: str) -> dict[str, Any]:
        return json.loads((self.discovery / f"network-{region}.private.json").read_text())

    def refresh(self) -> list[dict[str, Any]]:
        def read(region: str) -> list[dict[str, Any]]:
            response = aws(
                region,
                "ec2",
                "describe-instances",
                Filters=[
                    {"Name": "tag:SilkCampaign", "Values": [self.campaign]},
                    {
                        "Name": "instance-state-name",
                        "Values": ["pending", "running", "stopping", "stopped", "shutting-down"],
                    },
                ],
            )
            return [
                dict(i, Region=region) for r in response["Reservations"] for i in r["Instances"]
            ]

        with ThreadPoolExecutor(max_workers=4) as pool:
            instances = [i for rows in pool.map(read, self.regions) for i in rows]
        with self.lock:
            self.data["instances"] = instances
            self.save()
        return instances

    def ensure_groups(self, region: str, controller_ip: str) -> list[str]:
        network = self.network(region)
        valid = [s for s in network["subnets"] if s["az"] in network["offerings"]]
        if not valid:
            raise RuntimeError(f"no supported default subnet: {region}")
        vpc = valid[0]["vpc"]
        existing = aws(
            region,
            "ec2",
            "describe-security-groups",
            Filters=[{"Name": "tag:SilkCampaign", "Values": [self.campaign]}],
        )["SecurityGroups"]
        groups = {g["GroupName"]: g["GroupId"] for g in existing}
        ids = []
        for suffix in ["ssh", "peer-0", "peer-1", "peer-2", "peer-3"]:
            name = f"{self.campaign}-{suffix}"
            if name not in groups:
                response = aws(
                    region,
                    "ec2",
                    "create-security-group",
                    GroupName=name,
                    Description="Silk campaign SSH or TCP 9000 peer shard",
                    VpcId=vpc,
                    TagSpecifications=[
                        {"ResourceType": "security-group", "Tags": self.tags(suffix)}
                    ],
                )
                groups[name] = response["GroupId"]
            ids.append(groups[name])
        with self.lock:
            self.data["groups"][region] = ids
            self.save()
        try:
            aws(
                region,
                "ec2",
                "authorize-security-group-ingress",
                GroupId=ids[0],
                IpPermissions=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": controller_ip + "/32"}],
                    }
                ],
            )
        except AwsError as error:
            if error.code != "InvalidPermission.Duplicate":
                raise
        # Regions added after gateway selection must inherit its SSH ingress.
        # Otherwise all new hosts are routed through a gateway their SG blocks.
        gateway = self.data.get("ssh_gateway")
        if gateway:
            addresses = {gateway["address"]}
            if gateway["region"] == region:
                addresses.update(
                    i["PrivateIpAddress"]
                    for i in self.data["instances"]
                    if i["InstanceId"] == gateway["instance_id"] and i.get("PrivateIpAddress")
                )
            for address in sorted(addresses):
                try:
                    aws(
                        region,
                        "ec2",
                        "authorize-security-group-ingress",
                        GroupId=ids[0],
                        IpPermissions=[
                            dict(
                                IpProtocol="tcp",
                                FromPort=22,
                                ToPort=22,
                                IpRanges=[
                                    dict(
                                        CidrIp=address + "/32",
                                        Description="campaign-spare-ssh-gateway",
                                    )
                                ],
                            )
                        ],
                    )
                except AwsError as error:
                    if error.code != "InvalidPermission.Duplicate":
                        raise
        # Same-VPC traffic can arrive with a private source even when a public
        # endpoint was selected. All campaign instances share peer-0; reserve
        # one rule for that membership alongside its <=50 public /32 rules.
        try:
            aws(
                region,
                "ec2",
                "authorize-security-group-ingress",
                GroupId=ids[1],
                IpPermissions=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 9000,
                        "ToPort": 9000,
                        "UserIdGroupPairs": [{"GroupId": ids[1]}],
                    }
                ],
            )
        except AwsError as error:
            if error.code != "InvalidPermission.Duplicate":
                raise
        return ids

    def launch_region(self, region: str, count: int, controller_ip: str) -> None:
        if count <= 0:
            return
        network = self.network(region)
        subnets = sorted(
            [s for s in network["subnets"] if s["az"] in network["offerings"]],
            key=lambda s: (s["az"] in self.data.get("avoid_azs", {}).get(region, []), s["az"]),
        )
        groups = self.ensure_groups(region, controller_ip)
        ami = network["ubuntu_ami"]["id"]
        root = f"/home/ubuntu/{self.campaign}"
        # EC2 shutdown behavior=terminate makes this a controller-independent cost backstop.
        user_data = (
            "#!/bin/bash\nset -eu\n"
            f"install -d -o ubuntu -g ubuntu -m 0750 {root}\n"
            "shutdown -P +180\n"
        )
        for offset in range(0, count, 8):
            amount = min(8, count - offset)
            success = False
            for subnet in subnets:
                token = uuid.uuid4().hex
                with self.lock:
                    self.data["launches"].append(
                        {
                            "region": region,
                            "token": token,
                            "count": amount,
                            "az": subnet["az"],
                            "started_at": time.time(),
                        }
                    )
                    self.save()
                request = dict(
                    ImageId=ami,
                    InstanceType="t3a.medium",
                    KeyName=self.key["name"],
                    MinCount=amount,
                    MaxCount=amount,
                    ClientToken=token,
                    NetworkInterfaces=[
                        {
                            "DeviceIndex": 0,
                            "SubnetId": subnet["id"],
                            "AssociatePublicIpAddress": True,
                            "Groups": groups,
                        }
                    ],
                    BlockDeviceMappings=[
                        {
                            "DeviceName": network["ubuntu_ami"]["root"],
                            "Ebs": {
                                "VolumeSize": 24,
                                "VolumeType": "gp3",
                                "DeleteOnTermination": True,
                            },
                        }
                    ],
                    CreditSpecification={"CpuCredits": "unlimited"},
                    InstanceInitiatedShutdownBehavior="terminate",
                    MetadataOptions={"HttpTokens": "required"},
                    UserData=user_data,  # boto3 encodes EC2 UserData once
                    TagSpecifications=[
                        {"ResourceType": kind, "Tags": self.tags("candidate")}
                        for kind in ["instance", "volume"]
                    ],
                )
                for retry in range(2):
                    try:
                        aws(region, "ec2", "run-instances", **request)
                        success = True
                        break
                    except AwsError as error:
                        if error.code == "VcpuLimitExceeded":
                            # A rejected extra batch does not invalidate the
                            # candidates already allocated in this region.
                            with self.lock:
                                blocked = self.data.setdefault("quota_limited_regions", [])
                                if region not in blocked:
                                    blocked.append(region)
                                self.save()
                            print(
                                json.dumps(dict(event="spare-quota-limited", region=region)),
                                flush=True,
                            )
                            return
                        # Reconcile a lost response, and only retry the same idempotency token.
                        found = aws(
                            region,
                            "ec2",
                            "describe-instances",
                            Filters=[{"Name": "client-token", "Values": [token]}],
                        )["Reservations"]
                        if sum(len(r["Instances"]) for r in found) == amount:
                            success = True
                            break
                        if isinstance(error, AwsError) and error.code in {
                            "InsufficientInstanceCapacity",
                            "Unsupported",
                            "UnsupportedOperation",
                        }:
                            break
                        if retry == 1:
                            raise
                if success:
                    break
            if not success:
                raise RuntimeError(f"no instance capacity in supported AZs: {region}")

    def ensure_capacity(self, targets: dict[str, int]) -> None:
        limits = self.capacity_limits
        total_limit = sum(limits.values())
        if set(targets) - set(self.regions) or any(
            type(v) is not int or v < 0 or v > limits[r] for r, v in targets.items()
        ):
            raise RuntimeError("campaign fleet budget exceeded")
        # SSH sockets are direct; HTTPS proxy egress can have a different public IP.
        direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with direct.open("https://checkip.amazonaws.com", timeout=15) as response:
            controller_ip = response.read().decode().strip()
        import ipaddress

        ipaddress.IPv4Address(controller_ip)
        instances = self.refresh()
        counts = {r: sum(i["Region"] == r for i in instances) for r in self.regions}
        if (
            any(max(counts[r], targets.get(r, 0)) > limits[r] for r in self.regions)
            or sum(max(counts[r], targets.get(r, 0)) for r in self.regions) > total_limit
        ):
            raise RuntimeError("campaign fleet budget exceeded")

        def extend(region: str) -> None:
            extra = max(0, targets.get(region, 0) - counts[region])
            if extra:
                self.launch_region(region, extra, controller_ip)

        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(extend, self.regions))
        self.refresh()

    def host(self, instance: dict[str, Any]) -> Host:
        gateway = None
        spec = self.data.get("ssh_gateway")
        if (
            spec
            and instance["InstanceId"] != spec["instance_id"]
            and (
                self.settings.get("ssh_gateway_required") is True
                or instance["InstanceId"] not in self.data.get("direct_ssh_instances", [])
            )
        ):
            gateway = Host(**{**spec, "roles": tuple(spec["roles"])})
        return Host(
            alias=instance["InstanceId"],
            address=instance["PublicIpAddress"],
            user="ubuntu",
            region=instance["Region"],
            roles=("replica",),
            data_dir=f"/home/ubuntu/{self.campaign}",
            port=22,
            endpoint_address=instance["PublicIpAddress"],
            instance_id=instance["InstanceId"],
            identity_file=self.key["path"],
            ssh_gateway=gateway,
        )

    def _try_spare_gateway(self, hosts: list[Host], minimum: dict[str, int]) -> bool:
        required_gateway = self.settings.get("ssh_gateway_required") is True
        if (
            not required_gateway and self.settings.get("ssh_gateway_fallback") is not True
        ) or self.data.get("ssh_gateway"):
            return False
        counts = {r: sum(h.region == r for h in hosts) for r in self.regions}
        if not required_gateway and all(counts[r] >= minimum.get(r, 0) for r in self.regions):
            return False
        spares = [h for h in hosts if counts[h.region] > minimum.get(h.region, 0)]
        if not spares:
            return False
        gateway = replace(
            min(
                spares,
                key=lambda h: (
                    h.region != self.settings.get("ssh_gateway_region", "eu-west-1"),
                    -(counts[h.region] - minimum.get(h.region, 0)),
                    self.regions.index(h.region),
                    h.instance_id,
                ),
            ),
            roles=("spare",),  # Exclusively management; excluded from every replica inventory.
            ssh_gateway=None,
        )
        from .lifecycle import ensure_idle

        ensure_idle(gateway, 9000)
        environment = preflight(gateway, -1)
        instances = self.refresh()
        observed = next(i for i in instances if i["InstanceId"] == gateway.instance_id)
        self.data["ssh_gateway"] = asdict(gateway)
        self.data["ssh_gateway_preflight"] = environment
        self.data["direct_ssh_instances"] = sorted(h.instance_id for h in hosts)
        self.data["ssh_routing"] = "all-via-dedicated-gateway" if required_gateway else "fallback"
        self.save()
        aws(
            gateway.region,
            "ec2",
            "create-tags",
            Resources=[gateway.instance_id],
            Tags=[{"Key": "Role", "Value": "management-gateway"}],
        )
        for region, groups in self.data["groups"].items():
            addresses = {gateway.address}
            if region == gateway.region:
                addresses.add(observed["PrivateIpAddress"])
            for address in sorted(addresses):
                try:
                    aws(
                        region,
                        "ec2",
                        "authorize-security-group-ingress",
                        GroupId=groups[0],
                        IpPermissions=[
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 22,
                                "ToPort": 22,
                                "IpRanges": [
                                    {
                                        "CidrIp": address + "/32",
                                        "Description": "campaign-spare-ssh-gateway",
                                    }
                                ],
                            }
                        ],
                    )
                except AwsError as error:
                    if error.code != "InvalidPermission.Duplicate":
                        raise
        print(
            json.dumps(
                {
                    "event": "ssh-gateway-ready",
                    "region": gateway.region,
                    "reserved_spares": 1,
                    "routed_candidates": len(instances) - 1
                    if required_gateway
                    else len(instances) - len(hosts),
                }
            ),
            flush=True,
        )
        return True

    def ready_hosts(self, minimum: dict[str, int]) -> list[Host]:
        # One bounded boot wait per region, then one short probe per candidate.
        # Provisioned spares replace unreachable hosts; never rebuild the fleet in a loop.
        from .sdk import client

        instances = self.refresh()

        def boot(region):
            ids = [
                i["InstanceId"]
                for i in instances
                if i["Region"] == region and i["State"]["Name"] in {"pending", "running"}
            ]
            if ids:
                # A running VM may still refuse port 22 while sshd starts.
                from botocore.exceptions import WaiterError

                try:
                    client(region, "ec2", True).get_waiter("instance_status_ok").wait(
                        InstanceIds=ids, WaiterConfig={"Delay": 5, "MaxAttempts": 60}
                    )
                except WaiterError:
                    # One sick spare must not exclude the region's healthy instances.
                    print(json.dumps(dict(event="boot-wait-expired", region=region)), flush=True)

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(boot, self.regions))
        known, skipped = {}, set()
        for attempt in range(4):
            hosts = self._probe_hosts(minimum, known, skipped)
            if self._try_spare_gateway(hosts, minimum):
                if self.settings.get("ssh_gateway_required") is True:
                    known.clear()  # Requalify every target through the required gateway.
                skipped.clear()
                hosts = self._probe_hosts(minimum, known, skipped)
            gateway_id = self.data.get("ssh_gateway", {}).get("instance_id")
            if self.settings.get("ssh_gateway_required") is True and not gateway_id:
                raise RuntimeError("dedicated SSH gateway unavailable; direct execution prohibited")
            hosts = [h for h in hosts if h.instance_id != gateway_id]
            missing = {
                r: minimum[r] - sum(h.region == r for h in hosts)
                for r in minimum
                if sum(h.region == r for h in hosts) < minimum[r]
            }
            if not missing:
                return hosts
            if self.data.get("ssh_gateway"):
                # A shared gateway transport failure can reject many healthy
                # targets at once. Reconnect and retry them before buying spares.
                close_gateways()
                skipped.clear()
                hosts = self._probe_hosts(minimum, known, skipped)
                hosts = [h for h in hosts if h.instance_id != gateway_id]
                missing = {
                    r: minimum[r] - sum(h.region == r for h in hosts)
                    for r in minimum
                    if sum(h.region == r for h in hosts) < minimum[r]
                }
                if not missing:
                    return hosts
            if attempt == 3:
                raise RuntimeError(f"SSH unavailable after three spare additions: {missing}")
            self.add_spares(missing, unreachable=skipped)
            instances = self.refresh()
            with ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(boot, missing))
        raise AssertionError("unreachable")

    def add_spares(self, missing: dict[str, int], *, unreachable: set[str] | None = None) -> None:
        instances = self.refresh()
        # Once a real quota rejection establishes that growth is unavailable,
        # replace only failed qualification candidates, never a ready replica
        # or the management gateway. No capacity probes or quota polling.
        replaced = {}
        gateway_id = self.data.get("ssh_gateway", {}).get("instance_id")
        for region in missing:
            if region not in self.data.get("quota_limited_regions", []):
                continue
            ids = [
                i["InstanceId"]
                for i in instances
                if i["Region"] == region
                and i["InstanceId"] in (unreachable or set())
                and i["InstanceId"] != gateway_id
            ][: max(4, 2 * missing[region])]
            if ids:
                from .sdk import client

                aws(region, "ec2", "terminate-instances", InstanceIds=ids)
                client(region, "ec2", True).get_waiter("instance_terminated").wait(
                    InstanceIds=ids, WaiterConfig={"Delay": 5, "MaxAttempts": 36}
                )
                replaced[region] = len(ids)
                print(
                    json.dumps(
                        dict(event="replace-unreachable-spares", region=region, count=len(ids))
                    ),
                    flush=True,
                )
        if replaced:
            instances = self.refresh()
        targets = {r: sum(i["Region"] == r for i in instances) for r in self.regions}
        for region, deficit in missing.items():
            targets[region] += replaced.get(region, max(4, 2 * deficit))
        limits = {r: max(self.capacity_limits[r], targets[r]) for r in self.regions}
        if sum(limits.values()) > 200:
            raise RuntimeError("additional spares exceed the 200-peer security-group envelope")
        self.capacity_limits = limits
        self.data["capacity_limits"] = limits
        self.save()
        print(
            json.dumps(
                dict(
                    event="add-spares",
                    regions=list(missing),
                    requested=sum(replaced.get(r, max(4, 2 * d)) for r, d in missing.items()),
                )
            ),
            flush=True,
        )
        self.ensure_capacity(targets)

    def _probe_hosts(self, minimum: dict[str, int], known=None, skipped=None) -> list[Host]:
        known = {} if known is None else known
        skipped = set() if skipped is None else skipped
        errors = {}
        instances = [
            i
            for i in self.refresh()
            if i["State"]["Name"] == "running" and i.get("PublicIpAddress")
        ]

        def probe(instance):
            host = self.host(instance)
            if host.instance_id in known:
                return known[host.instance_id]
            if host.instance_id in skipped:
                return None
            try:
                with connect_once(host, connect_timeout=6) as connection:
                    result = connection.run(
                        "timeout 45 sh -c 'until test -f /var/lib/cloud/instance/boot-finished; "
                        "do sleep 1; done'",
                        hide=True,
                        warn=True,
                        in_stream=False,
                        timeout=50,
                    )
                    if not result.ok:
                        raise RuntimeError("cloud-init did not finish")
                known[host.instance_id] = host
                return host
            except (AuthenticationException, BadHostKeyException):
                raise
            except Exception as error:
                errors[host.instance_id] = type(error).__name__
                skipped.add(host.instance_id)
                return None

        with ThreadPoolExecutor(max_workers=8) as pool:
            ready = [host for host in pool.map(probe, instances) if host is not None]
        (self.state / "ssh-readiness.private.json").write_text(
            json.dumps(dict(ready=[h.instance_id for h in ready], errors=errors), indent=2),
            encoding="utf-8",
        )
        return sorted(ready, key=lambda h: (self.regions.index(h.region), h.instance_id))

    def configure_peers(self, hosts: list[Host]) -> None:
        peers = sorted({host.endpoint_address + "/32" for host in hosts})
        if len(peers) > 200:
            raise RuntimeError("peer rule shard capacity exceeded")

        def configure(region: str) -> None:
            ids = self.data["groups"].get(region)
            if not ids:
                return
            for shard, group in enumerate(ids[1:]):
                current = aws(region, "ec2", "describe-security-groups", GroupIds=[group])[
                    "SecurityGroups"
                ][0]
                desired = set(peers[shard * 50 : (shard + 1) * 50])
                present = {
                    item["CidrIp"]
                    for p in current["IpPermissions"]
                    for item in p.get("IpRanges", [])
                }
                for operation, addresses in [
                    ("revoke-security-group-ingress", present - desired),
                    ("authorize-security-group-ingress", desired - present),
                ]:
                    if addresses:
                        aws(
                            region,
                            "ec2",
                            operation,
                            GroupId=group,
                            IpPermissions=[
                                {
                                    "IpProtocol": "tcp",
                                    "FromPort": 9000,
                                    "ToPort": 9000,
                                    "IpRanges": [{"CidrIp": ip} for ip in sorted(addresses)],
                                }
                            ],
                        )

        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(configure, self.regions))

    def terminate_all(self) -> None:
        """Try every region independently; one failed API must not strand the others."""

        def cleanup_region(region: str) -> dict[str, Any]:
            filters = [{"Name": "tag:SilkCampaign", "Values": [self.campaign]}]
            try:
                response = aws(region, "ec2", "describe-instances", Filters=filters)
                ids = [
                    i["InstanceId"]
                    for r in response["Reservations"]
                    for i in r["Instances"]
                    if i["State"]["Name"] != "terminated"
                ]
                if ids:
                    aws(region, "ec2", "terminate-instances", InstanceIds=ids)
                    deadline = time.monotonic() + 180
                    while True:
                        response = aws(region, "ec2", "describe-instances", InstanceIds=ids)
                        if all(
                            i["State"]["Name"] == "terminated"
                            for r in response["Reservations"]
                            for i in r["Instances"]
                        ):
                            break
                        if time.monotonic() > deadline:
                            raise RuntimeError("instances-not-terminated")
                        time.sleep(5)
                groups = aws(region, "ec2", "describe-security-groups", Filters=filters)[
                    "SecurityGroups"
                ]
                for group in groups:
                    for attempt in range(12):
                        try:
                            aws(region, "ec2", "delete-security-group", GroupId=group["GroupId"])
                            break
                        except AwsError as error:
                            if error.code != "DependencyViolation" or attempt == 11:
                                raise
                            time.sleep(5)
                volumes = aws(region, "ec2", "describe-volumes", Filters=filters)["Volumes"]
                for volume in volumes:
                    if volume["State"] == "available":
                        aws(region, "ec2", "delete-volume", VolumeId=volume["VolumeId"])
                    else:
                        raise RuntimeError("campaign-volume-not-released")
                deadline = time.monotonic() + 60
                while aws(region, "ec2", "describe-volumes", Filters=filters)["Volumes"]:
                    if time.monotonic() > deadline:
                        raise RuntimeError("campaign-volume-remains")
                    time.sleep(3)
                return {"region": region, "live_instances": 0, "volumes": 0, "security_groups": 0}
            except Exception as error:
                return {"region": region, "error": str(error)}

        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(cleanup_region, self.regions))
        errors = [r for r in results if "error" in r]
        self.data["cleanup"] = {"completed_at": time.time(), "regions": results, "errors": errors}
        if not errors:
            self.data["instances"] = []
        self.save()
        if errors:
            raise RuntimeError("resource cleanup requires follow-up; see private ledger")
