import io
import time
from datetime import datetime
from http import HTTPStatus
from typing import Optional, Callable, Any, Dict, TypeVar, Tuple, List, Union, Iterable, Hashable, BinaryIO
from uuid import UUID

import requests
from nndict import nndict

from vdx_helper.mappers import permissions_mapper, file_mapper, get_paginated_mapper, credential_mapper, job_mapper, \
    verification_mapper, certificate_mapper, currency_mapper
from vdx_helper.typing import Json
from vdx_helper.util import optional_uuid_to_string, optional_uuids_to_string, uuids_to_string

T = TypeVar('T')

Dicterable = Union[Dict, Iterable[Tuple[Hashable, Any]]]


def get_json_mapper() -> Callable[[Json], Json]:
    def mapper(json_: Json) -> Json:
        return json_
    return mapper


class VDXError(Exception):

    def __init__(self, code: HTTPStatus, message: str):
        self.code = code
        self.message = message


def error_from_response(status, response):
    if status is not HTTPStatus.OK:
        try:
            json_response = response.json()
            description = json_response.get("description")
        except (ValueError, AttributeError):
            description = ""
        return VDXError(code=status, message=description)


class VDXHelper:

    def __init__(self, url: str, keycloak_url: str, core_api_key: str, core_api_client_id: str) -> None:
        self.url = url.rstrip("/")
        self.keycloak_url = keycloak_url
        self.auth_token: Optional[str] = None
        self.token_expiration_date: float = 0
        self.core_api_key: str = core_api_key
        self.core_api_client_id: str = core_api_client_id

    def _get_token_string(self) -> str:

        if self.auth_token is None or time.time() > self.token_expiration_date:
            status, self.auth_token, token_expiration_date = self._get_token()
            if self.auth_token is None or token_expiration_date is None:
                raise VDXError(status, "API Authentication failed")
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

    @property
    def header(self):
        headers = {
            "Authorization": "Bearer " + self._get_token_string(),
            "Accept": "application/json"
        }
        return headers

    ################## ENGINES #####################
    def get_partner_permissions(self, mapper: Optional[Callable[[Json], T]] = permissions_mapper) -> T:  # type: ignore # https://github.com/python/mypy/issues/3737

        response = requests.get(
            f"{self.url}/engines",
            headers=self.header
        )

        status = HTTPStatus(response.status_code)

        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)
        permissions = mapper(response.json())

        return permissions

    def get_engine_cost(self, engine_name: str, n: int,
                        mapper: Optional[Callable[[Json], T]] = currency_mapper) -> T:  # type: ignore # https://github.com/python/mypy/issues/3737

        response = requests.get(
            f"{self.url}/engines/{engine_name}/cost/{n}",
            headers=self.header
        )

        status = HTTPStatus(response.status_code)

        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        currency_cost = mapper(response.json())

        return currency_cost

    ################## FILES #####################
    def upload_file(self,
                    file_stream: BinaryIO,
                    ignore_duplicated: bool = False,
                    mapper: Callable[[Json], T] = file_mapper) -> T:  # type: ignore # https://github.com/python/mypy/issues/3737
        file_stream.seek(0)

        payload = {
            "file": (file_stream),
        }
        form_data = {
            "ignore_duplicated": ignore_duplicated
        }

        response = requests.post(
            f"{self.url}/files",
            headers=self.header,
            files=payload,
            data=form_data
        )

        status = HTTPStatus(response.status_code)

        if status not in [HTTPStatus.OK, HTTPStatus.CREATED]:
            raise error_from_response(status, response)

        file_summary = mapper(response.json())

        return file_summary

    def get_file_attributes(self, file_hash: str, mapper: Callable[[Json], T] = file_mapper) -> T:

        response = requests.get(
            f"{self.url}/files/{file_hash}/attributes",
            headers=self.header
        )

        status = HTTPStatus(response.status_code)

        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        file = mapper(response.json())

        return file

    def get_files(self, mapper: Callable[[Json], T] = get_paginated_mapper(file_mapper),
                  file_hash: Optional[str] = None, **pagination) -> T:  # type: ignore # https://github.com/python/mypy/issues/3737

        params = nndict(
            file_hash=file_hash,
            **pagination
        )

        response = requests.get(
            f"{self.url}/files",
            headers=self.header,
            params=params
        )

        status = HTTPStatus(response.status_code)

        if status not in [HTTPStatus.OK, HTTPStatus.CREATED]:
            raise error_from_response(status, response)
        files = mapper(response.json())

        return files

    ################## CREDENTIALS #####################
    def get_credentials(self, mapper: Callable[[Json], T] = get_paginated_mapper(credential_mapper), *,  # type: ignore # https://github.com/python/mypy/issues/3737
                        metadata: Dicterable = tuple(), uid: Optional[UUID] = None,
                        start_date: Optional[datetime] = None, end_date: Optional[datetime] = None,
                        and_tags: Optional[str] = None, or_tags: Optional[str] = None, **pagination) -> T:

        params = nndict(
            uid=optional_uuid_to_string(uid),
            upload_date_from=start_date,
            upload_date_until=end_date,
            and_tags=and_tags,
            or_tags=or_tags
        )

        metadata_filters = {key if key.startswith('metadata_') else f"metadata_{key}": value
                            for key, value in nndict(metadata)}

        params = {**params, **metadata_filters, **nndict(pagination)}

        response = requests.get(
            f"{self.url}/credentials",
            headers=self.header,
            params=params
        )

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        document_views = mapper(response.json())

        return document_views

    def get_credential(self, cred_uid: UUID, mapper: Callable[[Json], T] = credential_mapper) -> T:  # type: ignore # https://github.com/python/mypy/issues/3737

        response = requests.get(
            f"{self.url}/credentials/{cred_uid}",
            headers=self.header
        )

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        credential = mapper(response.json())

        return credential

    def create_credential(self, title: str, metadata: Dicterable, tags: Optional[Iterable[str]] = None,
                          file_hashes: Optional[List[str]] = None, cred_ids: List[UUID] = None,
                          expiry_date: Optional[str] = None, mapper: Callable[[Json], T] = credential_mapper) -> T:  # type: ignore # https://github.com/python/mypy/issues/3737
        payload = nndict(
            title=title,
            files=file_hashes,
            credentials=optional_uuids_to_string(cred_ids),
            tags=list(set(tags)) if tags is not None else None,
            expiry_date=expiry_date
        )
        payload_json = {**payload, "metadata": dict(metadata)}

        response = requests.post(
            f"{self.url}/credentials",
            headers=self.header,
            json=payload_json
        )

        status = HTTPStatus(response.status_code)
        if status not in [HTTPStatus.OK, HTTPStatus.CREATED]:
            raise error_from_response(status, response)

        document = mapper(response.json())

        return document

    def update_credential_tags(self, updated_credential_tags: Iterable[Dict[str, List[str]]]) -> None:

        payload = {
            "credentials": updated_credential_tags,
        }
        response = requests.patch(
            f"{self.url}/credentials",
            headers=self.header,
            json=payload
        )

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        return

    def replace_credential_tags(self, replace_credential_tags: Iterable[Dict[str, List[str]]]) -> None:

        payload = {
            "credentials": replace_credential_tags,
        }
        response = requests.put(
            f"{self.url}/credentials",
            headers=self.header,
            json=payload
        )

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        return

    def delete_credential_tag(self, cred_uid: UUID, tag: str) -> None:
        """
        Send a request to the "Delete Credential Tag" Endpoint

        :param cred_uid: The credential's UID
        :type cred_uid: UUID

        :param tag: The tag to be deleted
        :type tag: str
        """
        params = nndict(
            tag=tag
        )
        response = requests.patch(
            f"{self.url}/credentials/{cred_uid}/delete_tag",
            headers=self.header,
            params=params
        )

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

    def schedule_credentials(self, engine: str, credentials: List[UUID],
                             mapper: Callable[[Json], T] = job_mapper) -> T:  # type: ignore # https://github.com/python/mypy/issues/3737

        payload: Json = {
            "engine": engine,
            "credentials": uuids_to_string(credentials)
        }

        response = requests.post(
            f"{self.url}/credentials/schedule",
            headers=self.header,
            json=payload
        )

        status = HTTPStatus(response.status_code)
        if status not in [HTTPStatus.OK, HTTPStatus.CREATED]:
            raise error_from_response(status, response)

        job = mapper(response.json())

        return job

    def verify_by_credential_uid(self, cred_uid: UUID, mapper: Callable[[Json], T] = verification_mapper,
                                 **pagination) -> T:  # type: ignore # https://github.com/python/mypy/issues/3737

        params = {**nndict(pagination)}
        response = requests.get(
            f"{self.url}/verify/credential/{cred_uid}",
            headers=self.header,
            params=params
        )

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        verification_response = mapper(response.json())

        return verification_response

    ################## JOBS #####################
    def issue_job(self, engine: str, mapper: Callable[[Json], T] = job_mapper) -> T:  # type: ignore # https://github.com/python/mypy/issues/3737

        payload: Json = {
            "engine": engine
        }

        response = requests.post(
            f"{self.url}/jobs/immediate",
            headers=self.header,
            json=payload
        )

        status = HTTPStatus(response.status_code)
        if status not in [HTTPStatus.OK, HTTPStatus.CREATED]:
            raise error_from_response(status, response)

        job = mapper(response.json())

        return job

    def get_jobs(self, mapper: Callable[[Json], T] = get_paginated_mapper(job_mapper), *,  # type: ignore # https://github.com/python/mypy/issues/3737
                 job_status: Optional[str] = None, uid: Optional[UUID] = None,
                 start_date: Optional[datetime] = None, end_date: Optional[datetime] = None,
                 and_tags: Optional[str] = None, or_tags: Optional[str] = None, **pagination) -> T:

        params = nndict(
            uid=optional_uuid_to_string(uid),
            status=job_status,
            issued_date_from=start_date,
            issued_date_until=end_date,
            and_tags=and_tags,
            or_tags=or_tags
        )

        params = {**params, **nndict(pagination)}

        response = requests.get(
            f"{self.url}/jobs",
            headers=self.header,
            params=params
        )

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        issuer_jobs = mapper(response.json())

        return issuer_jobs

    def get_job(self, job_uid: UUID, mapper: Callable[[Json], T] = job_mapper) -> T:  # type: ignore # https://github.com/python/mypy/issues/3737

        response = requests.get(
            f"{self.url}/jobs/{job_uid}",
            headers=self.header
        )

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        job = mapper(response.json())

        return job

    def update_job_tags(self, updated_job_tags: List[dict]) -> None:

        payload: Json = {
            "jobs": updated_job_tags,
        }
        response = requests.patch(
            f"{self.url}/jobs",
            headers=self.header,
            json=payload
        )

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        return None

    def replace_job_tags(self, replace_job_tags: List[dict]) -> None:

        payload: Json = {
            "jobs": replace_job_tags,
        }
        response = requests.put(
            f"{self.url}/jobs",
            headers=self.header,
            json=payload
        )

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        return None

    ################## CERTIFICATES #####################
    def verify_by_uid(self, cert_uid: UUID, mapper: Callable[[Json], T] = verification_mapper) -> T:  # type: ignore # https://github.com/python/mypy/issues/3737

        response = requests.get(
            f"{self.url}/verify/{cert_uid}",
            headers=self.header
        )

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        verification_response = mapper(response.json())

        return verification_response

    def verify_by_certificate(self, filename: str,
                              file_stream: BinaryIO,
                              file_content_type: str,
                              mapper: Callable[[Json], T] = verification_mapper) -> T:  # type: ignore # https://github.com/python/mypy/issues/3737

        file_stream.seek(0)
        payload = {
            "file": (filename, file_stream, file_content_type)
        }

        response = requests.post(
            f"{self.url}/verify/upload/certificate",
            headers=self.header,
            files=payload
        )

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        verification_response = mapper(response.json())

        return verification_response

    def verify_by_file(self, filename: str,
                       file_stream: BinaryIO,
                       file_content_type: str, mapper: Callable[[Json], T] = verification_mapper,
                       **pagination) -> T:  # type: ignore # https://github.com/python/mypy/issues/3737

        payload = {
            "file": (filename, file_stream, file_content_type)
        }
        params = {**nndict(pagination)}

        response = requests.post(
            f"{self.url}/verify/upload/file",
            headers=self.header,
            files=payload,
            params=params
        )

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        verification_response = mapper(response.json())

        return verification_response

    def get_certificates(self, mapper: Callable[[Json], T] = get_paginated_mapper(certificate_mapper), *, # type: ignore # https://github.com/python/mypy/issues/3737
                         job_uid: Optional[UUID] = None, cred_uid: Optional[UUID] = None, uid: Optional[UUID] = None,
                         start_date: Optional[datetime] = None, end_date: Optional[datetime] = None,
                         and_credential_tags: Optional[str] = None, or_credential_tags: Optional[str] = None,
                         and_job_tags: Optional[str] = None, or_job_tags: Optional[str] = None,
                         verification_status: Optional[str] = None, **pagination) -> T:

        params = nndict(
            uid=optional_uuid_to_string(uid),
            job_uid=optional_uuid_to_string(job_uid),
            credential_uid=optional_uuid_to_string(cred_uid),
            issued_date_from=start_date,
            issued_date_until=end_date,
            and_credential_tags=and_credential_tags,
            or_credential_tags=or_credential_tags,
            and_job_tags=and_job_tags,
            or_job_tags=or_job_tags,
            verification_status=verification_status
        )

        params = {**params, **nndict(pagination)}

        response = requests.get(
            f"{self.url}/certificates",
            headers=self.header,
            params=params
        )

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        certificates_json = response.json()
        certificates = mapper(certificates_json)

        return certificates

    def revoke_certificate(self, cert_uid: UUID) -> None:

        response = requests.post(
            f"{self.url}/certificates/{cert_uid}/revoke",
            headers=self.header
        )

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        return

    def get_job_certificates(self, job_uid: UUID, and_tags: Optional[str] = None, or_tags: Optional[str] = None,
                             mapper: Callable[[Json], T] = get_paginated_mapper(certificate_mapper), **pagination) -> T:  # type: ignore # https://github.com/python/mypy/issues/3737

        params = nndict(
            and_tags=and_tags,
            or_tags=or_tags
        )

        params = {**params, **nndict(pagination)}

        response = requests.get(
            f"{self.url}/jobs/{job_uid}/certificates",
            headers=self.header,
            params=params
        )

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        certificates_json = response.json()
        certificates = mapper(certificates_json)

        return certificates

    def get_job_credentials(self, job_uid: UUID, and_tags: Optional[str] = None,
                            or_tags: Optional[str] = None, mapper: Callable[[Json], T] = get_paginated_mapper(credential_mapper),
                            **pagination) -> Optional[T]:  # type: ignore # https://github.com/python/mypy/issues/3737
        params = nndict(
            and_tags=and_tags,
            or_tags=or_tags
        )
        params = {**params, **nndict(pagination)}

        response = requests.get(
            f"{self.url}/jobs/{job_uid}/credentials",
            headers=self.header,
            params=params
        )

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        credentials = mapper(response.json())

        return credentials

    def download_certificate(self, cert_uid: UUID) -> io.BytesIO:

        response = requests.get(
            f"{self.url}/certificates/{cert_uid}/download",
            headers=self.header
        )

        status = HTTPStatus(response.status_code)

        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        certificate = io.BytesIO(response.content)

        return certificate

