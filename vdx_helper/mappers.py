from datetime import datetime
from typing import TypeVar, Callable, Dict, Any
from uuid import UUID

from vdx_helper.domain import VerificationStatus, StepStatus, JobStatus
from vdx_helper.models import File, PaginatedResponse, Credential, Job, VerificationResponse, \
    VerificationStepResult, Certificate, Claim, Partner, \
    VerificationReport
from vdx_helper.util import optional_datetime_from_string, datetime_from_string

T = TypeVar('T')


def json_mapper(json_: Dict[str, Any]) -> Dict[str, Any]:
    """
    Directly map any json response to a json response.

    :param json_: The json obtained from the endpoint call
    :type json_: Dict[str, Any]

    :return: The response in json format
    :rtype: Dict[str, Any]
    """
    return json_


def get_paginated_mapper(mapper: Callable[[Dict[str, Any]], T]) -> Callable[[Dict[str, Any]], 'PaginatedResponse']:
    """
    Obtain a mapper method that maps a json response from the Core API into a PaginatedResponse object containing
    a specific object as its items.

    :param mapper: The mapper to use to map the Paginated result's items
    :type mapper: Callable

    :return: A mapping function
    :rtype: Callable
    """
    def paginated_mapper(json_: Dict[str, Any]) -> 'PaginatedResponse':
        """
        Maps the json response into a Paginated Response object.

        :param json_: The json obtained from the endpoint call
        :type json_: Dict[str, Any]

        :return: A Paginated Response instance
        :rtype: class:`vdx_helper.models.PaginatedResponse`
        """
        return PaginatedResponse(
            page=int(json_["page"]),
            total_pages=int(json_["total_pages"]),
            per_page=int(json_["per_page"]),
            total_items=int(json_["total_items"]),
            items=[mapper(json_item) for json_item in json_["items"]]
        )

    return paginated_mapper


def file_mapper(json_: Dict[str, Any]) -> File:
    """
    Maps the json file response into a File object.

    :param json_: The json obtained from the endpoint call
    :type json_: Dict[str, Any]

    :return: A File instance
    :rtype: :class:`vdx_helper.models.File`
    """
    return File(
        file_hash=json_["file_hash"],
        file_type=json_["file_type"]
    )


def credential_mapper(json_: Dict[str, Any]) -> Credential:
    """
    Maps the json credential response into a Credential object.

    :param json_: The json obtained from the endpoint call
    :type json_: Dict[str, Any]

    :return: A Credential instance
    :rtype: :class:`vdx_helper.models.Credential`
    """
    return Credential(
        uid=UUID(json_["uid"]),
        title=json_["title"],
        metadata=json_["metadata"],
        files=[file_mapper(file) for file in json_["files"]],
        credentials=[credential_mapper(credential) for credential in json_["credentials"]],
        upload_date=datetime.fromisoformat(json_["upload_date"]),
        tags=json_["tags"],
        expiry_date=optional_datetime_from_string(json_["expiry_date"])
    )


def job_mapper(json_: Dict[str, Any]) -> Job:
    """
    Maps the json job response into a Job object.

    :param json_: The json obtained from the endpoint call
    :type json_: Dict[str, Any]

    :return: A Job instance
    :rtype: :class:`vdx_helper.models.Job`
    """
    return Job(
        uid=UUID(json_["uid"]),
        partner=partner_mapper(json_["partner"]),
        chain=json_["chain"],
        tags=json_["tags"],
        status=JobStatus(json_["status"]),
        created_date=datetime_from_string(json_["created_date"]),
        start_date=optional_datetime_from_string(json_.get("start_date")),
        issued_date=optional_datetime_from_string(json_.get("issued_date")),
        finished_date=optional_datetime_from_string(json_.get("finished_date")),
        failed_date=optional_datetime_from_string(json_.get("failed_date")),
        scheduled_date=optional_datetime_from_string(json_.get("scheduled_date"))
    )


def verification_mapper(json_: Dict[str, Any]) -> VerificationResponse:
    """
    Maps the json verification response into a VerificationResponse object.

    :param json_: The json obtained from the endpoint call
    :type json_: Dict[str, Any]

    :return: A VerificationResponse instance
    :rtype: :class:`vdx_helper.models.VerificationResponse`
    """
    return VerificationResponse(
        verification={key: verification_step_mapper(step) for key, step in json_["verification"].items()},
        result=verification_report_mapper(json_["result"])
    )


def verification_step_mapper(json_: Dict[str, Any]) -> VerificationStepResult:
    """
    Maps the json verification step result response into a Verification Step Result object.

    :param json_: The json obtained from the endpoint call
    :type json_: Dict[str, str]

    :return: A VerificationStepResult instance
    :rtype: :class:`vdx_helper.models.VerificationStepResult`
    """
    return VerificationStepResult(
        name=json_["name"],
        description=json_["description"],
        status=StepStatus(json_["status"])
    )


def partner_mapper(json_: Dict[str, Any]) -> Partner:
    """
    Maps the json partner response into a Partner object.

    :param json_: The json obtained from the endpoint call
    :type json_: Dict[str, Any]

    :return: A Partner instance
    :rtype: :class:`vdx_helper.models.Partner`
    """
    return Partner(
        **json_
    )


def claim_mapper(json_: Dict[str, Any]) -> Claim:
    """
    Maps the json claim response into a Claim object.

    :param json_: The json obtained from the endpoint call
    :type json_: Dict[str, Any]

    :return: A Claim instance
    :rtype: :class:`vdx_helper.models.Claim`
    """
    return Claim(
        uid=UUID(json_["uid"]),
        partner=partner_mapper(json_["partner"]),
        credential=credential_mapper(json_["credential"]),
        issued_date=datetime.fromisoformat(json_["issued_date"]),
        signature=json_["signature"]
    )


def certificate_mapper(json_: Dict[str, Any]) -> Certificate:
    """
    Maps the json certificate response into a Certificate object.

    :param json_: The json obtained from the endpoint call
    :type json_: Dict[str, Any]

    :return: A Certificate instance
    :rtype: :class:`vdx_helper.models.Certificate`
    """
    json_verification = json_.get("last_verification")
    return Certificate(
        certificate=claim_mapper(json_["certificate"]),
        revoked_date=optional_datetime_from_string(json_.get("revoked_date")),
        last_verification=verification_report_mapper(json_verification) if json_verification is not None else None
    )


def verification_report_mapper(json_: Dict[str, str]) -> VerificationReport:
    """
    Maps the json verification report response into a Verification Report object.

    :param json_: The json obtained from the endpoint call
    :type json_: Dict[str, str]

    :return: A VerificationReport instance
    :rtype: :class:`vdx_helper.models.VerificationReport`
    """
    return VerificationReport(
        status=VerificationStatus(json_["status"]),
        timestamp=datetime.fromisoformat(json_["timestamp"])
    )
