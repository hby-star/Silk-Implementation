"""Persistent AWS clients."""

from __future__ import annotations

import json
import os
import threading

import boto3
from botocore.config import Config

_lock = threading.Lock()
_clients = {}


def client(region: str, service: str, read_only: bool):
    # boto3 clients are thread-safe; construct Sessions only under this lock.
    proxy = os.environ.get("AWS_USE_PROXY", "").lower() in {"1", "true", "yes"}
    key = (region, service, read_only, proxy)
    with _lock:
        if key not in _clients:
            options = dict(
                connect_timeout=6,
                read_timeout=30,
                max_pool_connections=32,
                retries={"mode": "standard", "total_max_attempts": 3 if read_only else 1},
            )
            if not proxy:
                options["proxies"] = {}
            _clients[key] = boto3.Session(profile_name="default").client(
                service, region_name=region, config=Config(**options)
            )
        return _clients[key]


def call(region: str, service: str, operation: str, parameters: dict):
    read_only = operation.startswith(("describe-", "get-", "list-"))
    api = client(region, service, read_only)
    name = operation.replace("-", "_")
    if read_only and api.can_paginate(name):
        result = api.get_paginator(name).paginate(**parameters).build_full_result()
    else:
        result = getattr(api, name)(**parameters)
    result.pop("ResponseMetadata", None)
    return json.loads(json.dumps(result, default=lambda value: value.isoformat()))
