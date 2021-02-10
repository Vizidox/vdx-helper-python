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
    def paginated_mapper(json: Json) -> 'PaginatedView[T]':
        paginated_view = PaginatedView(
            page=int(json["page"]),
            total_pages=int(json["total_pages"]),
            per_page=int(json["per_page"]),
            total_items=int(json["total_items"]),
            items=[mapper(json_item) for json_item in json["items"]]
        )
        return paginated_view

    return paginated_mapper


def permissions_mapper(json: Json) -> List[EnginePermissionsView]:
    permission_views = list()
    for json_permission in json:
        permission = EnginePermissionsView(
            name=json_permission['name'],
            is_allowed=loads(json_permission['is_allowed']),
            show_prices=loads(json_permission["show_prices"])
        )
        permission_views.append(permission)
    return permission_views


def currency_mapper(json: Json) -> CurrencyAmountView:
    return CurrencyAmountView(
        amount=json["amount"],
        currency=json["currency"]
    )


def file_mapper(json: Json) -> FileView:
    return FileView(
        file_hash=json["file_hash"],
        file_type=json["file_type"]
    )


def credential_mapper(json: Json) -> CredentialView:
    return CredentialView(
        uid=UUID(json["uid"]),
        title=json["title"],
        metadata=json["metadata"],
        files=[file_mapper(file) for file in json["files"]],
        credentials=[credential_mapper(credential) for credential in json["credentials"]],
        upload_date=datetime.fromisoformat(json["upload_date"]),
        tags=json["tags"],
        expiry_date=optional_datetime_from_string(json["expiry_date"])
    )


def job_mapper(json: Json) -> JobView:
    return JobView(
        uid=UUID(json["uid"]),
        partner=partner_mapper(json["partner"]),
        chain=json["chain"],
        tags=json["tags"],
        status=JobStatus(json["status"]),
        created_date=optional_datetime_from_string(json.get("created_date")),
        start_date=optional_datetime_from_string(json.get("start_date")),
        issued_date=optional_datetime_from_string(json.get("issued_date")),
        finished_date=optional_datetime_from_string(json.get("finished_date")),
        failed_date=optional_datetime_from_string(json.get("failed_date")),
        scheduled_date=optional_datetime_from_string(json.get("scheduled_date"))
    )


def verification_mapper(json: Json) -> VerificationResponseView:
    return VerificationResponseView(
        verification=[verification_step_mapper(step) for step in json["verification"]]
    )


def verification_step_mapper(json: Json) -> VerificationStepResult:
    return VerificationStepResult(
        name=json["name"],
        description=json["description"],
        status=StepStatus(json["status"])
    )


def partner_mapper(json: Json):
    return PartnerView(
        **json
    )


def claim_mapper(json: Json) -> ClaimView:
    return ClaimView(
        uid=UUID(json["uid"]),
        partner=partner_mapper(json["partner"]),
        credential=credential_mapper(json["credential"]),
        issued_date=datetime.fromisoformat(json["issued_date"]),
        signature=json["signature"]
    )


def certificate_mapper(json: Json) -> CertificateView:
    return CertificateView(
        certificate=claim_mapper(json["certificate"]),
        last_verification=verification_report_mapper(json.get("last_verification"))
    )


def verification_report_mapper(json: Json) -> VerificationReport:
    return VerificationReport(
        status=VerificationStatus(json["status"]),
        timestamp=datetime.fromisoformat(json["timestamp"])
    )
