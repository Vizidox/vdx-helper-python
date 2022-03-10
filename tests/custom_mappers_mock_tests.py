from datetime import datetime
from uuid import UUID

from vdx_helper.domain import VerificationStatus, StepStatus, JobStatus
from vdx_helper.mappers import file_mapper, credential_mapper, partner_mapper
from vdx_helper.models import Credential, Job, VerificationResponse, VerificationStepResult, Certificate, \
    Claim, VerificationReport


def custom_credential_mapper(json_: dict) -> Credential:
    return Credential(
        uid=UUID(json_["uid"]),
        title=json_["title"],
        metadata=json_["metadata"],
        files=[file_mapper(file) for file in json_["files"]],
        credentials=[credential_mapper(credential) if 'credential' in json_["credentials"] else [] for credential in
                     json_["credentials"]],
        upload_date=datetime.fromisoformat(json_["upload_date"]),
        tags=json_["tags"],
        expiry_date=datetime.fromisoformat(json_["expiry_date"])
    )


def custom_job_mapper(json_: dict) -> Job:
    return Job(
        uid=UUID(json_["uid"]),
        partner=partner_mapper(json_["partner"]),
        chain=json_["chain"],
        tags=json_["tags"],
        status=JobStatus[json_["status"]],
        created_date=datetime.fromisoformat(json_["created_date"]),
        start_date=datetime.fromisoformat(json_["start_date"]) if "start_date" in json_ else None,
        issued_date=datetime.fromisoformat(json_["issued_date"]) if "issued_date" in json_ else None,
        finished_date=datetime.fromisoformat(json_["finished_date"]) if "finished_date" in json_ else None,
        failed_date=datetime.fromisoformat(json_["failed_date"]) if "failed_date" in json_ else None,
        scheduled_date=datetime.fromisoformat(json_["scheduled_date"]) if "scheduled_date" in json_ else None
    )


def custom_verification_mapper(json_: dict) -> VerificationResponse:
    return VerificationResponse(
        verification=[custom_verification_step_mapper(step) for step in json_["verification"]],
        result=custom_verification_report_mapper(json_["result"])
    )


def custom_verification_step_mapper(json_: dict) -> VerificationStepResult:
    return VerificationStepResult(
        name=json_["name"],
        description=json_["description"],
        status=StepStatus[json_["status"]]
    )


def custom_certificate_mapper(json_: dict) -> Certificate:
    return Certificate(
        certificate=custom_claim_mapper(json_["certificate"]),
        revoked_date=datetime.fromisoformat(json_.get("revoked_date")) if "revoked_date" in json_ else None,
        last_verification=custom_verification_report_mapper(json_.get("last_verification")) if "last_verification"
                                                                                               in json_ else None
    )


def custom_claim_mapper(json_: dict) -> Claim:
    return Claim(
        uid=UUID(json_["uid"]),
        partner=partner_mapper(json_["partner"]),
        credential=custom_credential_mapper(json_["credential"]),
        issued_date=datetime.fromisoformat(json_["issued_date"]),
        signature=json_["signature"]
    )


def custom_verification_report_mapper(json_: dict) -> VerificationReport:
    return VerificationReport(
        status=VerificationStatus[json_["status"]],
        timestamp=datetime.fromisoformat(json_["timestamp"])
    )
