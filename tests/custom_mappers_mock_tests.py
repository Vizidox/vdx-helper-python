from datetime import datetime
from typing import List
from uuid import UUID

from vdx_helper.mappers import file_mapper, credential_mapper, partner_mapper
from vdx_helper.models import EnginePermissionsView, CredentialView, JobView, JobStatus, VerificationResponseView, \
    VerificationStepResult, StepStatus, CertificateView, ClaimView, VerificationReport, VerificationStatus
from vdx_helper.typing import Json


def custom_permissions_mapper(_json: Json) -> List[EnginePermissionsView]:
    permission_views = list()
    for json_permission in _json:
        permission = EnginePermissionsView(
            name=json_permission['name'],
            is_allowed=json_permission['is_allowed'],
            # for some reason prism generates "python valid booleans" so no need for conversion
            show_prices=json_permission["show_prices"]
        )
        permission_views.append(permission)
    return permission_views


def custom_credential_mapper(json: Json) -> CredentialView:
    return CredentialView(
        uid=UUID(json["uid"]),
        title=json["title"],
        metadata=json["metadata"],
        files=[file_mapper(file) for file in json["files"]],
        credentials=[credential_mapper(credential) if 'credential' in json["credentials"] else [] for credential in
                     json["credentials"]],
        upload_date=datetime.fromisoformat(json["upload_date"]),
        tags=json["tags"],
        expiry_date=datetime.fromisoformat(json["expiry_date"])
    )


def custom_job_mapper(json: Json) -> JobView:
    return JobView(
        uid=UUID(json["uid"]),
        partner=partner_mapper(json["partner"]),
        chain=json["chain"],
        tags=json["tags"],
        status=JobStatus[json["status"]],
        created_date=datetime.fromisoformat(json["created_date"]),
        start_date=datetime.fromisoformat(json["start_date"]) if "start_date" in json else None,
        issued_date=datetime.fromisoformat(json["issued_date"]) if "issued_date" in json else None,
        finished_date=datetime.fromisoformat(json["finished_date"]) if "finished_date" in json else None,
        failed_date=datetime.fromisoformat(json["failed_date"]) if "failed_date" in json else None,
        scheduled_date=datetime.fromisoformat(json["scheduled_date"]) if "scheduled_date" in json else None
    )


def custom_verification_mapper(json: Json) -> VerificationResponseView:
    return VerificationResponseView(
        verification=[custom_verification_step_mapper(step) for step in json["verification"]]
    )


def custom_verification_step_mapper(json: Json) -> VerificationStepResult:
    return VerificationStepResult(
        name=json["name"],
        description=json["description"],
        status=StepStatus[json["status"]]
    )


def custom_certificate_mapper(json: Json) -> CertificateView:
    return CertificateView(
        certificate=custom_claim_mapper(json["certificate"]),
        last_verification=custom_verification_report_mapper(json["last_verification"]) if "last_verification" in json else None
    )


def custom_claim_mapper(json: Json) -> ClaimView:
    return ClaimView(
        uid=UUID(json["uid"]),
        partner=partner_mapper(json["partner"]),
        credential=custom_credential_mapper(json["credential"]),
        issued_date=datetime.fromisoformat(json["issued_date"]),
        signature=json["signature"]
    )


def custom_verification_report_mapper(json: Json) -> VerificationReport:
    return VerificationReport(
        status=VerificationStatus[json["status"]],
        timestamp=datetime.fromisoformat(json["timestamp"])
    )