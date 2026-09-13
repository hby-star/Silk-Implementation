from __future__ import annotations

from enum import Enum


class UnsupportedExperiment(ValueError):
    """The requested experiment is not part of the experiment registry."""


class ExecutionMode(str, Enum):
    LOCAL_PROCESS = "local-process"
    DISTRIBUTED = "distributed"


class BeaconImplementation(str, Enum):
    SILK = "silk-beacon"
    RONDO = "rondo-beacon"
    SPURT = "spurt-beacon"

    @classmethod
    def parse(cls, value: str) -> BeaconImplementation:
        try:
            return cls(value)
        except ValueError as error:
            supported = ", ".join(item.value for item in cls)
            raise UnsupportedExperiment(
                f"unsupported beacon implementation {value!r}; supported values are {supported}"
            ) from error


class BeaconExecutor(str, Enum):
    DOCKER = "docker"
    AWS_REMOTE = "remote-aws"

    @classmethod
    def parse(cls, value: str) -> BeaconExecutor:
        try:
            return cls(value)
        except ValueError as error:
            supported = ", ".join(item.value for item in cls)
            raise UnsupportedExperiment(
                f"unsupported beacon executor {value!r}; supported values are {supported}"
            ) from error

    @property
    def network_scenario(self) -> str:
        return {
            BeaconExecutor.DOCKER: "definition-bound-docker-network",
            BeaconExecutor.AWS_REMOTE: "aws-native-wan-v1",
        }[self]

    @property
    def resource_profile(self) -> str:
        return {
            BeaconExecutor.DOCKER: "definition-bound-docker-resources",
            BeaconExecutor.AWS_REMOTE: "aws-one-instance-per-node-v1",
        }[self]

    @property
    def clock_profile(self) -> tuple[str, bool]:
        if self is BeaconExecutor.AWS_REMOTE:
            return "multi-host-barrier-aligned-monotonic", True
        return "single-host-shared-system-clock", True

    @property
    def clock_aggregation_mode(self) -> str:
        if self is BeaconExecutor.AWS_REMOTE:
            return "barrier-aligned-monotonic"
        return "synchronized-unix"


class BavssExecutor(str, Enum):
    DOCKER_AGGREGATE = "docker-aggregate"
    AWS_AGGREGATE = "aws-aggregate"

    @classmethod
    def parse(cls, value: str) -> BavssExecutor:
        try:
            return cls(value)
        except ValueError as error:
            supported = ", ".join(item.value for item in cls)
            raise UnsupportedExperiment(
                f"unsupported bAVSS executor {value!r}; supported values are {supported}"
            ) from error


class ExperimentKind(str, Enum):
    BAVSS_PHASE_COST = "bavss-phase-cost"
    BEACON_PERFORMANCE = "beacon-performance"

    @property
    def execution_mode(self) -> ExecutionMode:
        if self is ExperimentKind.BAVSS_PHASE_COST:
            return ExecutionMode.LOCAL_PROCESS
        return ExecutionMode.DISTRIBUTED

    @classmethod
    def parse(cls, value: str) -> ExperimentKind:
        try:
            return cls(value)
        except ValueError as error:
            supported = ", ".join(item.value for item in cls)
            raise UnsupportedExperiment(
                f"unsupported experiment_id {value!r}; supported IDs are {supported}"
            ) from error
