from datetime import datetime
from uuid import UUID

from vdx_helper.models import FileView, EnginePermissionsView, CredentialView, PaginatedView, JobView, PartnerView, \
    JobStatus, VerificationResponseView, VerificationStepResult, StepStatus, CertificateView, ClaimView, \
    VerificationReport, VerificationStatus, CurrencyAmountView

engine_json = [
    {
        "name": "bitcoin",
        "is_allowed": "true",
        "show_prices": "true"
    },
    {
        "name": "dogecoin",
        "is_allowed": "false",
        "show_prices": "false"
    }
]

engine_cost_json = {"amount": 10.467, "currency": 'bitcoin'}

mapped_engine_cost = CurrencyAmountView(amount=10.467, currency="bitcoin")

mapped_engine_permissions = [EnginePermissionsView(name="bitcoin", is_allowed=True, show_prices=True),
                             EnginePermissionsView(name="dogecoin", is_allowed=False, show_prices=False)]

file_json = {
    "file_hash": "hash",
    "file_type": "type"
}

paginated_file = {
    "page": "1",
    "total_pages": "1",
    "per_page": "20",
    "total_items": "1",
    "items": [file_json]
}

mapped_file = FileView(file_hash="hash", file_type="type")

mapped_paginated_file = PaginatedView(page=1, total_pages=1, per_page=20, total_items=1,
                                      items=[mapped_file])


credential_json = {
    "uid": "189e4e5c-833d-430b-9baa-5230841d997f",
    "title": "title",
    "metadata": {},
    "files": [file_json],
    "credentials": [],
    "upload_date": "2020-01-01T11:29:28.977178+00:00",
    "tags": ["example"],
    "expiry_date": "2021-01-01T15:34:05.814607+00:00"
}

mapped_credential = CredentialView(uid=UUID("189e4e5c-833d-430b-9baa-5230841d997f"), title="title", metadata={},
                                   files=[mapped_file], credentials=[],
                                   upload_date=datetime.fromisoformat('2020-01-01T11:29:28.977178+00:00'),
                                   tags=["example"],
                                   expiry_date=datetime.fromisoformat("2021-01-01T15:34:05.814607+00:00"))

paginated_credential = {
    "page": "1",
    "total_pages": "1",
    "per_page": "20",
    "total_items": "1",
    "items": [credential_json]
}

mapped_paginated_credential = PaginatedView(page=1, total_pages=1, per_page=20, total_items=1,
                                            items=[mapped_credential])

partner_json = {
    "id": "partner_id",
    "name": "partner"
}
job_json = {
    "uid": "123e4567-e89b-12d3-a456-426655440000",
    "partner": partner_json,
    "chain": "dogecoin",
    "tags": [
        "tag1"
    ],
    "status": JobStatus.scheduled.name,
    "created_date": "2020-11-13T11:30:00.790190+00:00",
    "scheduled_date": "2020-11-13T12:00:00+00:00"
}

paginated_job = {
    "page": "1",
    "total_pages": "1",
    "per_page": "20",
    "total_items": "1",
    "items": [job_json]
}

mapped_partner = PartnerView(id="partner_id", name="partner")
mapped_job = JobView(uid=UUID("123e4567-e89b-12d3-a456-426655440000"),
                     partner=mapped_partner,
                     chain='dogecoin',
                     tags=["tag1"],
                     status=JobStatus.scheduled,
                     created_date=datetime.fromisoformat("2020-11-13T11:30:00.790190+00:00"),
                     scheduled_date=datetime.fromisoformat("2020-11-13T12:00:00+00:00"),
                     start_date=None,
                     issued_date=None,
                     finished_date=None,
                     failed_date=None
                     )

mapped_paginated_job = PaginatedView(page=1, total_pages=1, per_page=20, total_items=1,
                                     items=[mapped_job])

verification_response_json = {
    "verification": [
        {
            "name": "Checking certificate integrity",
            "description": {
                "hash_function": "SHA256",
                "actual_hash": "d08f0971320c1cb70dcff0f5356bf8cd90ce4d03b4e13b9c82137c4ab1a3e659",
                "expected_hash": "d08f0971320c1cb70dcff0f5356bf8cd90ce4d03b4e13b9c82137c4ab1a3e659"
            },
            "status": StepStatus.passed.name
        },
        {
            "name": "Checking revocation date",
            "description": {
                "revocation_address": "myWUoZBBiMyBLHWKtNayfgduUWFed6bzCi",
                "revocation_address_url": "https://chain.so/address/BTCTEST/myWUoZBBiMyBLHWKtNayfgduUWFed6bzCi",
                "revocation_date": None
            },
            "status": StepStatus.failed.name
        }
    ]
}
mapped_verification_step_1 = VerificationStepResult(name='Checking certificate integrity',
                                                    description={
                                                        "hash_function": "SHA256",
                                                        "actual_hash": "d08f0971320c1cb70dcff0f5356bf8cd90ce4d03b4e13b9c82137c4ab1a3e659",
                                                        "expected_hash": "d08f0971320c1cb70dcff0f5356bf8cd90ce4d03b4e13b9c82137c4ab1a3e659"
                                                    },
                                                    status=StepStatus.passed)

mapped_verification_step_2 = VerificationStepResult(name='Checking revocation date',
                                                    description={
                                                        "revocation_address": "myWUoZBBiMyBLHWKtNayfgduUWFed6bzCi",
                                                        "revocation_address_url": "https://chain.so/address/BTCTEST/myWUoZBBiMyBLHWKtNayfgduUWFed6bzCi",
                                                        "revocation_date": None
                                                    },
                                                    status=StepStatus.failed)

mapped_verification = VerificationResponseView([mapped_verification_step_1, mapped_verification_step_2])

certificate_json = {
    "certificate": {
        "uid": "123e4567-e89b-12d3-a456-426655440000",
        "partner": partner_json,
        "credential": credential_json,
        "issued_date": "2020-02-11T15:34:05.813217+00:00",
        "signature": "signature"
    },
    "last_verification": {
        "status": VerificationStatus.ok.name,
        "timestamp": "2020-02-11T15:34:05.813289+00:00"
    }
}

paginated_certificate = {
    "page": "1",
    "total_pages": "1",
    "per_page": "20",
    "total_items": "1",
    "items": [certificate_json]
}

mapped_claim = ClaimView(uid=UUID("123e4567-e89b-12d3-a456-426655440000"),
                         partner=mapped_partner,
                         credential=mapped_credential,
                         issued_date=datetime.fromisoformat("2020-02-11T15:34:05.813217+00:00"),
                         signature='signature')
mapped_verification_report = VerificationReport(status=VerificationStatus.ok,
                                                timestamp=datetime.fromisoformat("2020-02-11T15:34:05.813289+00:00"))
mapped_certificate = CertificateView(certificate=mapped_claim, last_verification=mapped_verification_report)

mapped_paginated_certificate = PaginatedView(page=1, total_pages=1, per_page=20, total_items=1,
                                             items=[mapped_certificate])
