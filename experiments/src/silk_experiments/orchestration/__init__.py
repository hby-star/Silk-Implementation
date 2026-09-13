from .local import run_local_suite
from .model import SuiteResult
from .remote import run_remote_suite

__all__ = ["SuiteResult", "run_local_suite", "run_remote_suite"]
