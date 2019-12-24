import time
import os
import io
import requests
from http import HTTPStatus
from typing import Optional, Tuple, Callable, Any, Dict, List, TypeVar, NamedTuple
from uuid import UUID
from werkzeug.datastructures import FileStorage
from flask import request

T = TypeVar('T')
Json = Dict[str, Any]

def get_json_mapper() -> Callable[[Json], Json]:
    def mapper(json_: Json) -> Json:
        return json_
    return mapper

class FileSummary(NamedTuple):
    id: str
    file_hash: str
    filename: str
    public: bool
    encrypted: bool
    encrypted_hash: Optional[str]
    picture_file: bool

class VDXError(Exception):
    pass


class VDXHelper:
    def __init__(self, url: str, keycloak_url: str, core_api_key: str, core_api_client_id: str) -> None:
        self.url = url
        self.keycloak_url = keycloak_url
        self.auth_token: Optional[str] = None
        self.token_expiration_date: float = 0
        self.core_api_key: str = core_api_key
        self.core_api_client_id: str = core_api_client_id

    def _compute_core_file_id(self, file_hash: str) -> str:
        return f"{self.core_api_client_id}_{file_hash}"

    def _get_token_string(self) -> str:

        if self.auth_token is None or time.time() > self.token_expiration_date:
            status, self.auth_token, token_expiration_date = self._get_token()
            if self.auth_token is None or token_expiration_date is None:
                raise VDXError("API Authentication failed")
            else:
                self.token_expiration_date = token_expiration_date

        return self.auth_token

    def _get_token(self) -> Tuple[HTTPStatus, Optional[str], Optional[float]]:

        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }

        payload = {
            "client_id": self.core_api_client_id,
            "client_secret": self.core_api_key,
            "grant_type": "client_credentials"
        }

        response = requests.post(f"{self.keycloak_url}",
                                 headers=headers,
                                 data=payload)

        status = HTTPStatus(response.status_code)
        access_token = None
        token_expiration_date = None

        if status is HTTPStatus.OK:
            json_response = response.json()
            access_token = str(json_response['access_token'])
            token_expiration_date = time.time() + int(json_response['expires_in'])

        return status, access_token, token_expiration_date

    def _get_request_header(self):
        headers = {
            "Authorization": "Bearer " + self._get_token_string(),
            "Accept": "application/json"
        }
        return headers

    ################## ENGINES #####################
    def engine_cost(self, engine_name: str, n: int,  mapper: Callable[[Json], T] = get_json_mapper()) -> Tuple[HTTPStatus, Optional[T]]:  # type: ignore # https://github.com/python/mypy/issues/3737
        response = requests.get(
            f"{self.url}/engines/{engine_name}/cost/{n}",
            headers=self._get_request_header()
        )

        status = HTTPStatus(response.status_code)
        currency_amount = None

        if status is HTTPStatus.OK:
            currency_amount = mapper(response.json())

        return status, currency_amount

    def get_partner_permissions(self, mapper: Callable[[Json], T] = get_json_mapper()) -> Tuple[HTTPStatus, Optional[T]]:  # type: ignore # https://github.com/python/mypy/issues/3737

        response = requests.get(
            f"{self.url}/engines",
            headers=self._get_request_header()
        )

        status = HTTPStatus(response.status_code)
        permissions = None

        if status is HTTPStatus.OK:
            permissions = mapper(response.json())

        return status, permissions

    ################## FILES #####################
    def upload_file(self, file: FileStorage, mapper: Callable[[], T] = get_json_mapper()) -> Tuple[HTTPStatus, Optional[T]]:  # type: ignore # https://github.com/python/mypy/issues/3737

        file.stream.seek(0)

        payload = {
            "file": (file.filename, file.stream, file.content_type)
        }

        response = requests.post(
            f"{self.url}/files",
            headers=self._get_request_header(),
            files=payload
        )

        status = HTTPStatus(response.status_code)
        file_summary = None

        if status in [HTTPStatus.OK, HTTPStatus.CREATED]:
            file_summary = mapper(response.json())

        return status, file_summary

    def update_file_attributes(self, file_summary: FileSummary, filename: str) -> HTTPStatus:

        payload = {
            "filename": filename
        }

        core_id = self._compute_core_file_id(file_summary.encrypted_hash) if file_summary.encrypted_hash \
            else self._compute_core_file_id(file_summary.file_hash)

        response = requests.put(
            f"{self.url}/files/{core_id}/attributes",
            headers=self._get_request_header(),
            json=payload
        )

        return HTTPStatus(response.status_code)

    ################## CREDENTIALS #####################
    def download_credential_file(self, doc_uid: UUID) -> Tuple[HTTPStatus, Optional[io.BytesIO]]:

        response = requests.get(
            f"{self.url}/credentials/{doc_uid}/file",
            headers=self._get_request_header()
        )

        status = HTTPStatus(response.status_code)
        document_file = None

        if status is HTTPStatus.OK:
            document_file = io.BytesIO(response.content)

        return status, document_file

    def get_credentials(self, mapper: Callable[[Json], T] = get_json_mapper()) -> Tuple[HTTPStatus, Optional[T]]:  # type: ignore # https://github.com/python/mypy/issues/3737

        params = self._get_pagination_params()

        response = requests.get(
            f"{self.url}/credentials",
            headers=self._get_request_header(),
            params=params
        )

        document_views = None

        status = HTTPStatus(response.status_code)
        if status is HTTPStatus.OK:
            document_views = mapper(response.json())

        return status, document_views

    def get_credential(self, cred_uid: UUID, mapper: Callable[[Json], T] = get_json_mapper()) -> Tuple[HTTPStatus, Optional[T]]:  # type: ignore # https://github.com/python/mypy/issues/3737

        response = requests.get(
            f"{self.url}/credentials/{cred_uid}",
            headers=self._get_request_header()
        )

        credential = None

        status = HTTPStatus(response.status_code)
        if status is HTTPStatus.OK:
            credential = mapper(response.json())

        return status, credential

    def create_credential(self, title: str, metadata: dict, file_summary: FileSummary, mapper: Callable[[Json], T] = get_json_mapper()) -> Tuple[HTTPStatus, Optional[T]]:  # type: ignore # https://github.com/python/mypy/issues/3737

        core_id = self._compute_core_file_id(file_summary.encrypted_hash) if file_summary.encrypted_hash \
            else self._compute_core_file_id(file_summary.file_hash)

        payload: Json = {
            "title": title,
            "metadata": metadata,
            "file_id": core_id
        }

        response = requests.post(
            f"{self.url}/credentials",
            headers=self._get_request_header(),
            json=payload
        )

        credential = None

        status = HTTPStatus(response.status_code)
        if status in [HTTPStatus.OK, HTTPStatus.CREATED]:
            credential = mapper(response.json())

        return status, credential

    ################## JOBS #####################
    def issue_job(self, engine: str, credentials: List[UUID], expiry_date: Optional[str], mapper: Callable[[Json], T] = get_json_mapper()) -> Tuple[HTTPStatus, Optional[T]]:  # type: ignore # https://github.com/python/mypy/issues/3737

        payload: Json = {
            "engine": engine,
            "credentials": credentials,
            "expiry_date": expiry_date
        }

        response = requests.post(
            f"{self.url}/jobs",
            headers=self._get_request_header(),
            json=payload
        )

        job = None

        status = HTTPStatus(response.status_code)
        if status in [HTTPStatus.OK, HTTPStatus.CREATED]:
            job = mapper(response.json())

        return status, job

    def get_jobs(self, mapper: Callable[[Json], T] = get_json_mapper()) -> Tuple[HTTPStatus, Optional[T]]:  # type: ignore # https://github.com/python/mypy/issues/3737

        params = self._get_pagination_params()

        response = requests.get(
            f"{self.url}/jobs",
            headers=self._get_request_header(),
            params=params
        )

        issuer_jobs = None

        status = HTTPStatus(response.status_code)
        if status is HTTPStatus.OK:
            issuer_jobs = mapper(response.json())

        return status, issuer_jobs

    def get_job(self, job_uid: UUID, mapper: Callable[[Json], T] = get_json_mapper()) -> Tuple[HTTPStatus, Optional[T]]:  # type: ignore # https://github.com/python/mypy/issues/3737

        response = requests.get(
            f"{self.url}/jobs/{job_uid}",
            headers=self._get_request_header()
        )

        job = None

        status = HTTPStatus(response.status_code)
        if status is HTTPStatus.OK:
            job = mapper(response.json())

        return status, job

    ################## CERTIFICATES #####################
    def verify_by_uid(self, cert_uid: UUID, mapper: Callable[[Json], T] = get_json_mapper()) -> Tuple[HTTPStatus, Optional[T]]:  # type: ignore # https://github.com/python/mypy/issues/3737

        response = requests.get(
            f"{self.url}/verify/{cert_uid}",
            headers=self._get_request_header()
        )

        verification_response = None
        status = HTTPStatus(response.status_code)
        if status is HTTPStatus.OK:
            verification_response = mapper(response.json())

        return status, verification_response

    def verify_by_certificate(self, file: FileStorage, mapper: Callable[[Json], T] = get_json_mapper()) -> Tuple[HTTPStatus, Optional[T]]:  # type: ignore # https://github.com/python/mypy/issues/3737

        file.stream.seek(0)
        payload = {
            "file": (file.filename, file.stream, file.content_type)
        }

        response = requests.post(
            f"{self.url}/verify/upload/certificate",
            headers=self._get_request_header(),
            files=payload
        )

        verification_response = None
        status = HTTPStatus(response.status_code)
        if status is HTTPStatus.OK:
            verification_response = mapper(response.json())

        return status, verification_response

    def verify_by_file(self, file: FileStorage, mapper: Callable[[Json], T] = get_json_mapper()) -> Tuple[HTTPStatus, Optional[T]]:  # type: ignore # https://github.com/python/mypy/issues/3737

        payload = {
            "file": (file.filename, file.stream, file.content_type)
        }

        response = requests.post(
            f"{self.url}/verify/upload/file",
            headers=self._get_request_header(),
            files=payload
        )

        verification_response = None
        status = HTTPStatus(response.status_code)
        if status is HTTPStatus.OK:
            verification_response = mapper(response.json())

        return status, verification_response

    def get_certificates(self, mapper: Callable[[Json], T] = get_json_mapper()) -> Tuple[HTTPStatus, Optional[T]]:  # type: ignore # https://github.com/python/mypy/issues/3737

        params = self._get_pagination_params()

        response = requests.get(
            f"{self.url}/certificates",
            headers=self._get_request_header(),
            params=params
        )

        certificates = None

        status = HTTPStatus(response.status_code)
        if status is HTTPStatus.OK:
            certificates_json = response.json()
            certificates = mapper(certificates_json)

        return status, certificates

    def revoke_certificate(self, cert_uid: UUID) -> HTTPStatus:

        response = requests.post(
            f"{self.url}/certificates/{cert_uid}/revoke",
            headers=self._get_request_header()
        )

        return HTTPStatus(response.status_code)

    def get_job_certificates(self, job_uid: UUID, mapper: Callable[[Json], T] = get_json_mapper()) -> Tuple[HTTPStatus, Optional[T]]:  # type: ignore # https://github.com/python/mypy/issues/3737

        params = self._get_pagination_params()

        response = requests.get(
            f"{self.url}/jobs/{job_uid}/certificates",
            headers=self._get_request_header(),
            params=params
        )

        certificates = None

        status = HTTPStatus(response.status_code)
        if status is HTTPStatus.OK:
            certificates_json = response.json()
            certificates = mapper(certificates_json)

        return status, certificates

    def download_certificate(self, cert_uid: UUID) ->Tuple[HTTPStatus, Optional[io.BytesIO]]:

        response = requests.get(
            f"{self.url}/certificates/{cert_uid}/download",
            headers=self._get_request_header()
        )

        status = HTTPStatus(response.status_code)
        certificate = None

        if status is HTTPStatus.OK:
            certificate = io.BytesIO(response.content)

        return status, certificate

    @staticmethod
    def _get_pagination_params():
        params = {
            'count': 0,
            'page': 1
        }
        if request.args.get('filterby'):
            params['filterby'] = request.args.get('filterby')
        if request.args.get('sortby'):
            params['sortby'] = request.args.get('sortby')
        if request.args.get('order'):
            params['order'] = request.args.get('order')

        return params




