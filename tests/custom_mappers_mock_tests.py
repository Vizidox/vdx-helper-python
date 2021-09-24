from datetime import datetime
from typing import List
from uuid import UUID

from vdx_helper.mappers import file_mapper, credential_mapper, partner_mapper
from vdx_helper.models import EnginePermissionsView, CredentialView, JobView, JobStatus, VerificationResponseView, \
    VerificationStepResult, StepStatus, CertificateView, ClaimView, VerificationReport, VerificationStatus
from vdx_helper.typing import Json


def custom_permissions_mapper(json_: Json) -> List[EnginePermissionsView]:
    permission_views = list()
    for json_permission in json_:
        permission = EnginePermissionsView(
            name=json_permission['name'],
            is_allowed=json_permission['is_allowed'],
            # for some reason prism generates "python valid booleans" so no need for conversion
            show_prices=json_permission["show_prices"]
        )
        permission_views.append(permission)
    return permission_views


def custom_credential_mapper(json_: Json) -> CredentialView:
    return CredentialView(
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


def custom_job_mapper(json_: Json) -> JobView:
    return JobView(
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


def custom_verification_mapper(json_: Json) -> VerificationResponseView:
    return VerificationResponseView(
        verification=[custom_verification_step_mapper(step) for step in json_["verification"]],
        result=custom_verification_report_mapper(json_["result"])
    )


def custom_verification_step_mapper(json_: Json) -> VerificationStepResult:
    return VerificationStepResult(
        name=json_["name"],
        description=json_["description"],
        status=StepStatus[json_["status"]]
    )


def custom_certificate_mapper(json_: Json) -> CertificateView:
    return CertificateView(
        certificate=custom_claim_mapper(json_["certificate"]),
        revoked_date=datetime.fromisoformat(json_.get("revoked_date")) if "revoked_date" in json_ else None,
        last_verification=custom_verification_report_mapper(json_.get("last_verification")) if "last_verification"
                                                                                               in json_ else None
    )


def custom_claim_mapper(json_: Json) -> ClaimView:
    return ClaimView(
        uid=UUID(json_["uid"]),
        partner=partner_mapper(json_["partner"]),
        credential=custom_credential_mapper(json_["credential"]),
        issued_date=datetime.fromisoformat(json_["issued_date"]),
        signature=json_["signature"]
    )


def custom_verification_report_mapper(json_: Json) -> VerificationReport:
    return VerificationReport(
        status=VerificationStatus[json_["status"]],
        timestamp=datetime.fromisoformat(json_["timestamp"])
    )