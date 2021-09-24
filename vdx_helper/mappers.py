from datetime import datetime
from json import loads
from typing import List, TypeVar, Callable
from uuid import UUID

from vdx_helper.typing import Json
from vdx_helper.models import EnginePermissionsView, FileView, PaginatedView, CredentialView, JobView, JobStatus, \
    VerificationResponseView, VerificationStepResult, StepStatus, CertificateView, ClaimView, PartnerView, \
    VerificationReport, VerificationStatus, CurrencyAmountView
from vdx_helper.util import optional_datetime_from_string

T = TypeVar('T')


def get_paginated_mapper(mapper: Callable[[Json], T]) -> Callable[[Json], 'PaginatedView[T]']:
    def paginated_mapper(json_: Json) -> 'PaginatedView[T]':
        paginated_view = PaginatedView(
            page=int(json_["page"]),
            total_pages=int(json_["total_pages"]),
            per_page=int(json_["per_page"]),
            total_items=int(json_["total_items"]),
            items=[mapper(json_item) for json_item in json_["items"]]
        )
        return paginated_view

    return paginated_mapper


def permissions_mapper(json_: Json) -> List[EnginePermissionsView]:
    permission_views = []
    for json_permission in json_:
        permission = EnginePermissionsView(
            name=json_permission['name'],
            is_allowed=loads(json_permission['is_allowed']),
            show_prices=loads(json_permission["show_prices"])
        )
        permission_views.append(permission)
    return permission_views


def currency_mapper(json_: Json) -> CurrencyAmountView:
    return CurrencyAmountView(
        amount=json_["amount"],
        currency=json_["currency"]
    )


def file_mapper(json_: Json) -> FileView:
    return FileView(
        file_hash=json_["file_hash"],
        file_type=json_["file_type"]
    )


def credential_mapper(json_: Json) -> CredentialView:
    return CredentialView(
        uid=UUID(json_["uid"]),
        title=json_["title"],
        metadata=json_["metadata"],
        files=[file_mapper(file) for file in json_["files"]],
        credentials=[credential_mapper(credential) for credential in json_["credentials"]],
        upload_date=datetime.fromisoformat(json_["upload_date"]),
        tags=json_["tags"],
        expiry_date=optional_datetime_from_string(json_["expiry_date"])
    )


def job_mapper(json_: Json) -> JobView:
    return JobView(
        uid=UUID(json_["uid"]),
        partner=partner_mapper(json_["partner"]),
        chain=json_["chain"],
        tags=json_["tags"],
        status=JobStatus(json_["status"]),
        created_date=optional_datetime_from_string(json_.get("created_date")),
        start_date=optional_datetime_from_string(json_.get("start_date")),
        issued_date=optional_datetime_from_string(json_.get("issued_date")),
        finished_date=optional_datetime_from_string(json_.get("finished_date")),
        failed_date=optional_datetime_from_string(json_.get("failed_date")),
        scheduled_date=optional_datetime_from_string(json_.get("scheduled_date"))
    )


def verification_mapper(json_: Json) -> VerificationResponseView:
    return VerificationResponseView(
        verification=[verification_step_mapper(step) for step in json_["verification"]],
        result=verification_report_mapper(json_["result"])
    )


def verification_step_mapper(json_: Json) -> VerificationStepResult:
    return VerificationStepResult(
        name=json_["name"],
        description=json_["description"],
        status=StepStatus(json_["status"])
    )


def partner_mapper(json_: Json):
    return PartnerView(
        **json_
    )


def claim_mapper(json_: Json) -> ClaimView:
    return ClaimView(
        uid=UUID(json_["uid"]),
        partner=partner_mapper(json_["partner"]),
        credential=credential_mapper(json_["credential"]),
        issued_date=datetime.fromisoformat(json_["issued_date"]),
        signature=json_["signature"]
    )


def certificate_mapper(json_: Json) -> CertificateView:
    json_verification = json_.get("last_verification")
    return CertificateView(
        certificate=claim_mapper(json_["certificate"]),
        revoked_date=optional_datetime_from_string(json_.get("revoked_date")),
        last_verification=verification_report_mapper(json_verification) if json_verification is not None else None
    )


def verification_report_mapper(json_: Json) -> VerificationReport:
    return VerificationReport(
        status=VerificationStatus(json_["status"]),
        timestamp=datetime.fromisoformat(json_["timestamp"])
    )
