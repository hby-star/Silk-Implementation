"""Read-only discovery for native AWS experiments; resource identities remain private."""

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .fleet import aws


def discover_networks(regions: list[str], output: Path, key_name: str) -> None:
    output.mkdir(parents=True, exist_ok=True)

    def inspect(region: str) -> None:
        aws(region, "ec2", "describe-key-pairs", KeyNames=[key_name])
        offerings = [
            x["Location"]
            for x in aws(
                region,
                "ec2",
                "describe-instance-type-offerings",
                LocationType="availability-zone",
                Filters=[{"Name": "instance-type", "Values": ["t3a.medium"]}],
            )["InstanceTypeOfferings"]
        ]
        subnets = aws(
            region,
            "ec2",
            "describe-subnets",
            Filters=[
                {"Name": "default-for-az", "Values": ["true"]},
            ],
        )["Subnets"]
        routes = aws(region, "ec2", "describe-route-tables")["RouteTables"]
        acls = aws(region, "ec2", "describe-network-acls")["NetworkAcls"]
        usable = []
        for subnet in subnets:
            if (
                subnet["AvailabilityZone"] not in offerings
                or not subnet["MapPublicIpOnLaunch"]
                or subnet["AvailableIpAddressCount"] < 20
            ):
                continue
            tables = [
                t
                for t in routes
                if any(a.get("SubnetId") == subnet["SubnetId"] for a in t["Associations"])
            ] or [
                t
                for t in routes
                if t["VpcId"] == subnet["VpcId"] and any(a.get("Main") for a in t["Associations"])
            ]
            if not any(
                r.get("DestinationCidrBlock") == "0.0.0.0/0"
                and r.get("GatewayId", "").startswith("igw-")
                and r.get("State") == "active"
                for t in tables
                for r in t["Routes"]
            ):
                continue
            # A modified NACL needs explicit network planning, not optimistic provisioning.
            subnet_acls = [
                a
                for a in acls
                if any(x["SubnetId"] == subnet["SubnetId"] for x in a["Associations"])
            ]
            if len(subnet_acls) != 1:
                continue
            entries = subnet_acls[0]["Entries"]
            if not all(
                any(
                    e.get("CidrBlock") == "0.0.0.0/0"
                    and e["Protocol"] == "-1"
                    and e["RuleAction"] == "allow"
                    and e["Egress"] == direction
                    and not any(
                        d["Egress"] == direction
                        and "CidrBlock" in d
                        and d["RuleNumber"] < e["RuleNumber"]
                        for d in entries
                    )
                    for e in entries
                )
                for direction in (False, True)
            ):
                continue
            usable.append(
                dict(
                    id=subnet["SubnetId"],
                    vpc=subnet["VpcId"],
                    az=subnet["AvailabilityZone"],
                    public=True,
                    available=subnet["AvailableIpAddressCount"],
                )
            )
        if not usable or len({s["vpc"] for s in usable}) != 1:
            raise RuntimeError(f"no unambiguous public default-subnet network: {region}")
        images = aws(
            region,
            "ec2",
            "describe-images",
            Owners=["099720109477"],
            Filters=[
                {
                    "Name": "name",
                    "Values": ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"],
                },
                {"Name": "state", "Values": ["available"]},
                {"Name": "architecture", "Values": ["x86_64"]},
                {"Name": "virtualization-type", "Values": ["hvm"]},
            ],
        )["Images"]
        if not images:
            raise RuntimeError(f"Ubuntu 22.04 amd64 AMI unavailable: {region}")
        ami = max(images, key=lambda x: x["CreationDate"])
        value = dict(
            region=region,
            offerings=offerings,
            subnets=usable,
            routes=routes,
            acls=acls,
            ubuntu_ami=dict(
                id=ami["ImageId"],
                root=ami["RootDeviceName"],
                name=ami["Name"],
                created=ami["CreationDate"],
            ),
        )
        (output / f"network-{region}.private.json").write_text(
            json.dumps(value, indent=2) + "\n", encoding="utf-8"
        )

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(inspect, regions))
