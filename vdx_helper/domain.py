from enum import Enum


class VerificationStatus(Enum):
    """
    A representation of all possible verification status
    """
    ok = 'ok'
    pending = 'pending'
    expired = 'expired'
    revoked = 'revoked'
    failed = 'failed'
    error = 'error'


class StepStatus(Enum):
    """
    A representation of all status of a verification step.
    """
    not_started = 'not_started'
    passed = 'passed'
    pending = 'pending'
    failed = 'failed'
    error = 'error'


class JobStatus(Enum):
    """
    A representation of all possible status of a Job.
    """
    failed = 'failed'
    started = 'started'
    unconfirmed = 'unconfirmed'
    pending = 'pending'
    finished = 'finished'
    scheduled = 'scheduled'
