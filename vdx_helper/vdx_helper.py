import io
import time
from datetime import datetime
from http import HTTPStatus
from typing import Optional, Callable, Dict, TypeVar, Tuple, List, Iterable, BinaryIO, Any
from uuid import UUID

import requests
from nndict import nndict
from vdx_helper.errors import error_from_response, VDXError
from vdx_helper.mappers import file_mapper, get_paginated_mapper, credential_mapper, job_mapper, \
    certificate_mapper, verification_mapper
from vdx_helper.util import optional_uuid_to_string, optional_uuids_to_string, datetime_from_string, uuids_to_string

T = TypeVar('T')


class VDXHelper:
    """
    Helper class that allows its users to connect to the VDX Core API with little fuss. Each method corresponds to
    an endpoint on the Core API, including all of its parameters. By default, the results are mapped into specific
    objects, but a JSON mapper can also be used (directly returns the results in JSON), as well as custom mappers.
    More information on mappers on the :mod:`vdx_helper.mappers` module.

    To use, create an instance of this class by providing the required information, and then invoke any of the
    available methods. The authentication flow is fully dealt with by this class, as long as the correct client secret
    and URL is provided.

    :param api_url: The url for the VDX Core API. For example, https://vizidox.com/api
    :type api_url: str

    :param auth_url: The url for the VDX Core API authentication server. For example, https://vizidox.com/auth
    :type auth_url: str

    :param client_secret: The client secret for authentication
    :type client_secret: str

    :param client_id: The client ID for authentication
    :type client_id: str
    """

    def __init__(self, api_url: str, auth_url: str, client_secret: str, client_id: str) -> None:
        self.api_url = api_url.rstrip("/")
        self.auth_url = auth_url
        self.client_secret: str = client_secret
        self.client_id: str = client_id

        self.auth_token: Optional[str] = None
        self.token_expiration_date: float = 0

    def _fetch_token(self) -> Tuple[str, float]:
        """
        Retrieves a usable authentication token from the Vizidox Authentication Server, with the set-up
        client_id and client_secret.

        :raises VDXError: Raised when there is an issue with the request to the Authentication server

        :return: A tuple containing the token and its expiration date
        :rtype: Tuple[str, float]
        """
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }

        payload = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "client_credentials"
        }

        response = requests.post(f"{self.auth_url}", headers=headers, data=payload)

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise VDXError(status, "API Authentication failed")

        access_token = str(response.json()['access_token'])
        token_expiration_date = time.time() + int(response.json()['expires_in'])

        return access_token, token_expiration_date

    @property
    def _token(self) -> str:
        """
        Checks if there is a token stored in the helper, and if it is expired. If there is no token or if it is
        expired, then a new one is retrieved from the authentication server. Finally, the currently valid token
        is returned.

        :return: The authentication token
        :rtype: str
        """
        if self.auth_token is None or time.time() > self.token_expiration_date:
            self.auth_token, token_expiration_date = self._fetch_token()
            self.token_expiration_date = token_expiration_date

        return self.auth_token

    @property
    def header(self) -> Dict[str, Any]:
        """
        Creates a header structure to be used by all requests for authentication.

        :return: The request header
        :rtype: Dict[str, Any]
        """
        return {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}

    def upload_file(self,
                    file_stream: BinaryIO,
                    ignore_duplicated: bool = False,
                    mapper: Callable[[Dict[str, Any]], T] = file_mapper) -> T:
        """
        Upload a file to the Core API servers.

        :param file_stream: File to be uploaded
        :type file_stream: BinaryIO

        :param ignore_duplicated: Flag indicating if duplicate files should be ignored. If true, and the file has
                                  already been uploaded previously, it will be re-uploaded
        :type ignore_duplicated: bool

        :param mapper: Optional mapper to change the format of the endpoint response
        :type mapper: :class:`typing.Callable`

        :return: The result of the endpoint call
        :rtype: :class:`T`
        """
        file_stream.seek(0)
        payload = {"file": (file_stream)}
        form_data = {"ignore_duplicated": ignore_duplicated}

        response = requests.post(f"{self.api_url}/files", headers=self.header, files=payload, data=form_data)

        status = HTTPStatus(response.status_code)
        if status not in [HTTPStatus.OK, HTTPStatus.CREATED]:
            raise error_from_response(status, response)

        return mapper(response.json()["result"])

    def get_file(self, file_hash: str, mapper: Callable[[Dict[str, Any]], T] = file_mapper) -> T:
        """
        Retrieve file details by its hash.

        :param file_hash: File hash to retrieve
        :type file_hash: str

        :param mapper: Optional mapper to change the format of the endpoint response
        :type mapper: :class:`typing.Callable`

        :return: The result of the endpoint call
        :rtype: :class:`T`
        """
        response = requests.get(f"{self.api_url}/files/{file_hash}", headers=self.header)

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        return mapper(response.json()["result"])

    def get_files(self, mapper: Callable[[Dict[str, Any]], T] = get_paginated_mapper(file_mapper),
                  file_hash: Optional[str] = None, **pagination: Dict[str, Any]) -> T:
        """
        Retrieve all files uploaded by the Partner, or filter them via their hash.

        :param mapper: Optional mapper to change the format of the endpoint response
        :type mapper: :class:`typing.Callable`

        :param file_hash: File hash to filter by
        :type file_hash: str, optional

        :param pagination: Keyword arguments for pagination
        :type pagination: Dict[str, Any]

        :return: The result of the endpoint call
        :rtype: :class:`T`
        """

        params = nndict(file_hash=file_hash, **pagination)
        response = requests.get(f"{self.api_url}/files", headers=self.header, params=params)

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)
        return mapper(response.json()["result"])

    def get_credentials(self, mapper: Callable[[Dict[str, Any]], T] = get_paginated_mapper(credential_mapper), *,
                        metadata: Optional[Dict[str, Any]] = None, uid: Optional[UUID] = None,
                        start_date: Optional[datetime] = None, end_date: Optional[datetime] = None,
                        and_tags: Optional[str] = None, or_tags: Optional[str] = None, **pagination: Dict[str, Any]) -> T:
        """
        Retrieve all partner credentials, or filter by metadata values, uid,
        upload_date (start_date < upload_date < end_date), and tags.

        More information on tags on the `VDX Core API <https://docs.vizidox.com/#tags>`__ official documentation.
        Results are paginated, and the pagination parameters should be provided as keyword arguments.

        For more information on the possible parameters, check the
        `VDX Core API <https://docs.vizidox.com/#pagination>`__ official documentation.

        :param mapper: Optional mapper to change the format of the endpoint response
        :type mapper: :class:`typing.Callable`

        :param metadata: Metadata values to filter by. A dictionary is expected with the key corresponding to the
                         field name found in the metadata, and the value corresponding to that field's value.
        :type metadata: dict, optional

        :param uid: Credential UID to filter by
        :type uid: :class:`uuid.UUID`, optional

        :param start_date: Filter by Credentials uploaded after the given start_date
        :type start_date: :class:`datetime.datetime`, optional

        :param end_date: Filter by Credentials uploaded before the given end_date
        :type end_date: :class:`datetime.datetime`, optional

        :param and_tags: Filter Credentials that contain all the given tags
        :type and_tags: List[str], optional

        :param or_tags: Filter Credentials that contain at least one of the given tags
        :type or_tags: List[str], optional

        :param pagination: Keyword arguments for pagination
        :type pagination: Dict[str, Any]

        :return: The result of the endpoint call
        :rtype: :class:`T`
        """
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

        response = requests.get(f"{self.api_url}/credentials", headers=self.header, params=params)

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        return mapper(response.json()["result"])

    def get_credential(self, cred_uid: UUID, mapper: Callable[[Dict[str, Any]], T] = credential_mapper) -> T:
        """
        Retrieve a specific credential from the Core API, via its UUID.

        :param cred_uid: Credential UID to obtain
        :type cred_uid: :class:`uuid.UUID`

        :param mapper: Optional mapper to change the format of the endpoint response
        :type mapper: :class:`typing.Callable`

        :return: The result of the endpoint call
        :rtype: :class:`T`
        """
        response = requests.get(f"{self.api_url}/credentials/{cred_uid}", headers=self.header)

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        return mapper(response.json()["result"])

    def create_credential(self, title: str, metadata: Dict[str, Any], tags: Optional[Iterable[str]] = None,
                          file_hashes: Optional[List[str]] = None, cred_ids: List[UUID] = None,
                          expiry_date: Optional[str] = None,
                          mapper: Callable[[Dict[str, Any]], T] = credential_mapper) -> T:
        """
        Create a new credential from a previously uploaded file, or provided metadata.

        :param title: The title of the credential
        :type title: str

        :param metadata: Metadata values to filter by. A dictionary is expected with the key corresponding to the
                         field name found in the metadata, and the value corresponding to that field's value. Can be
                         an empty dictionary as long as at least one file hash is provided.
        :type metadata: Dict[str, Any]

        :param tags: Optional text tags that can be used to identify and filter the credential. Must have at least
                    3 characters, and can only contain alphanumeric characters, '-' or '_'
        :type tags: Iterable[str], optional

        :param file_hashes: List of hashes of files to associate to the credential. Must be hashes of files previously
                            uploaded to the core API. Can be None as long as provided metadata is not empty.
        :type file_hashes: List[str], optional

        :param cred_ids: List of credentials to associate to the new credential.
        :type cred_ids: List[:class:`uuid.UUID`], optional

        :param expiry_date: Date the credential should expire, if applicable
        :type expiry_date: :class:`datetime.datetime`, optional

        :param mapper: Optional mapper to change the format of the endpoint response
        :type mapper: :class:`typing.Callable`

        :return: The result of the endpoint call
        :rtype: :class:`T`
        """
        payload = nndict(
            title=title,
            files=file_hashes,
            credentials=optional_uuids_to_string(cred_ids),
            tags=list(set(tags)) if tags is not None else None,
            expiry_date=expiry_date
        )
        payload_json = {**payload, "metadata": dict(metadata)}
        response = requests.post(f"{self.api_url}/credentials", headers=self.header, json=payload_json)

        status = HTTPStatus(response.status_code)
        if status not in [HTTPStatus.OK, HTTPStatus.CREATED]:
            raise error_from_response(status, response)

        return mapper(response.json()["result"])

    def update_credential_tags(self, updated_credential_tags: Iterable[Dict[str, List[str]]]) -> None:
        """
        Add new tags to one or more credentials. Previous credential tags are not changed.

        Example format of the parameter:

        .. code-block:: json

            [
                {
                    "credential_uid": "81fe5e08-46e4-11ec-81d3-0242ac130003",
                    "tags": ["tagA","tagB","tagC"]
                },
                {
                    "credential_uid": "7f026924-b3f8-4670-bc65-37fd7da8867c",
                    "tags": ["tagD"]
                }
            ]

        :param updated_credential_tags: Dictionary containing the credential UUIDs to update and the new tags to add
        :type updated_credential_tags: Dict[str, List[str]]
        """
        payload = {"credentials": updated_credential_tags}
        response = requests.patch(f"{self.api_url}/credentials", headers=self.header, json=payload)

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        return

    def replace_credential_tags(self, replace_credential_tags: Iterable[Dict[str, List[str]]]) -> None:
        """
        Replaces all the given credential tags with the new ones.

        Example format of the parameter:

        .. code-block:: json

            [
                {
                    "credential_uid": "81fe5e08-46e4-11ec-81d3-0242ac130003",
                    "tags": ["tagA","tagB","tagC"]
                },
                {
                    "credential_uid": "7f026924-b3f8-4670-bc65-37fd7da8867c",
                    "tags": ["tagD"]
                }
            ]

        :param replace_credential_tags: Dictionary containing the credential UUIDs to update and the new tags to replace
                                        the old ones with
        :type replace_credential_tags: dict
        """
        payload = {"credentials": replace_credential_tags}
        response = requests.put(f"{self.api_url}/credentials", headers=self.header, json=payload)

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        return

    def delete_credential_tag(self, cred_uid: UUID, tag: str) -> None:
        """
        Deletes a specific tag from the given credential.

        :param cred_uid: UUID of the credential to update
        :type cred_uid: :class:`uuid.UUID`

        :param tag: Tag to delete
        :type tag: str
        """
        params = nndict(tag=tag)
        response = requests.patch(f"{self.api_url}/credentials/{cred_uid}/delete_tag",
                                  headers=self.header,
                                  params=params)

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

    def schedule_credentials(self, engine: str, credentials: List[UUID],
                             mapper: Callable[[Dict[str, Any]], T] = job_mapper) -> T:
        """
        Schedule the given list of credentials to be issued on the Blockchain engine.

        :param engine: Blockchain Engine to schedule the credentials
        :type engine: str

        :param credentials: List of UUIDs of the credentials to schedule
        :type credentials: List[:class:`uuid.UUID`]

        :param mapper: Optional mapper to change the format of the endpoint response
        :type mapper: :class:`typing.Callable`

        :return: The result of the endpoint call
        :rtype: :class:`T`
        """
        payload = {
            "engine": engine,
            "credentials": uuids_to_string(credentials)
        }
        response = requests.post(f"{self.api_url}/credentials/schedule", headers=self.header, json=payload)

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.CREATED:
            raise error_from_response(status, response)

        return mapper(response.json()["result"])

    def issue_job(self, engine: str, mapper: Callable[[Dict[str, Any]], T] = job_mapper) -> T:
        """
        Immediately issues the next scheduled job for the given blockchain engine, if there are scheduled credentials.

        :param engine: Blockchain engine to issue
        :type engine: str

        :param mapper: Optional mapper to change the format of the endpoint response
        :type mapper: :class:`typing.Callable`

        :return: The result of the endpoint call
        :rtype: :class:`T`
        """
        payload = {"engine": engine}

        response = requests.post(f"{self.api_url}/jobs/immediate", headers=self.header, json=payload)

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.CREATED:
            raise error_from_response(status, response)

        return mapper(response.json()["result"])

    def get_jobs(self, mapper: Callable[[Dict[str, Any]], T] = get_paginated_mapper(job_mapper), *,
                 job_status: Optional[str] = None, uid: Optional[UUID] = None,
                 start_date: Optional[datetime] = None, end_date: Optional[datetime] = None,
                 and_tags: Optional[str] = None, or_tags: Optional[str] = None, **pagination: Dict[str, Any]) -> T:
        """
        Retrieve all partner jobs, or filter by a specific status, uid,
        issued date (start_date < issued_date < end_date), and tags.

        More information on tags on the `VDX Core API <https://docs.vizidox.com/#tags>`__ official documentation.
        Results are paginated, and the pagination parameters should be provided as keyword arguments.
        For more information on the possible parameters, check the
        `VDX Core API <https://docs.vizidox.com/#pagination>`__ official documentation.

        :param mapper: Optional mapper to change the format of the endpoint response
        :type mapper: :class:`typing.Callable`

        :param job_status: Filter jobs with the given status
        :type job_status: str, optional

        :param uid: Job UID to filter by
        :type uid: :class:`uuid.UUID`, optional

        :param start_date: Filter Jobs that were issued after the given start_date
        :type start_date: :class:`datetime.datetime`, optional

        :param end_date: Filter Jobs that were issued before the given end_date
        :type end_date: :class:`datetime.datetime`, optional

        :param and_tags: Filter Jobs that contain all the given tags
        :type and_tags: List[str], optional

        :param or_tags: Filter Jobs that contain at least one of the given tags
        :type or_tags: List[str], optional

        :param pagination: Keyword arguments for pagination
        :type pagination: Dict[str, Any]

        :return: The result of the endpoint call
        :rtype: :class:`T`
        """
        params = nndict(
            uid=optional_uuid_to_string(uid),
            status=job_status,
            issued_date_from=start_date,
            issued_date_until=end_date,
            and_tags=and_tags,
            or_tags=or_tags
        )

        params = {**params, **nndict(pagination)}
        response = requests.get(f"{self.api_url}/jobs", headers=self.header, params=params)

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        return mapper(response.json()["result"])

    def get_job(self, job_uid: UUID, mapper: Callable[[Dict[str, Any]], T] = job_mapper) -> T:
        """
        Retrieve a specific job from the Core API, via its UUID.

        :param job_uid: Job UID to obtain
        :type job_uid: :class:`uuid.UUID`

        :param mapper: Optional mapper to change the format of the endpoint response
        :type mapper: :class:`typing.Callable`

        :return: The result of the endpoint call
        :rtype: :class:`T`
        """
        response = requests.get(f"{self.api_url}/jobs/{job_uid}", headers=self.header)

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        return mapper(response.json()["result"])

    def update_job_tags(self, updated_job_tags: List[Dict[str, Any]]) -> None:
        """
        Add new tags to one or more jobs. Previous job tags are not changed.

        Example format of the parameter:

        .. code-block:: json

            [
                {
                    "job_uid": "81fe5e08-46e4-11ec-81d3-0242ac130003",
                    "tags": ["tagA","tagB","tagC"]
                },
                {
                    "job_uid": "7f026924-b3f8-4670-bc65-37fd7da8867c",
                    "tags": ["tagD"]
                }
            ]

        :param updated_job_tags: Dictionary containing the job UUIDs to update and the new tags to add
        :type updated_job_tags: Dict[str, Any]
        """
        payload = {"jobs": updated_job_tags}
        response = requests.patch(f"{self.api_url}/jobs", headers=self.header, json=payload)

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        return None

    def replace_job_tags(self, replace_job_tags: List[Dict[str, Any]]) -> None:
        """
        Replaces all the given job tags with the new ones.

        Example format of the parameter:

        .. code-block:: json

            [
                {
                    "job_uid": "81fe5e08-46e4-11ec-81d3-0242ac130003",
                    "tags": ["tagA","tagB","tagC"]
                },
                {
                    "job_uid": "7f026924-b3f8-4670-bc65-37fd7da8867c",
                    "tags": ["tagD"]
                }
            ]

        :param replace_job_tags: Dictionary containing the job UUIDs to update and the new tags to replace
                                 the old ones with
        :type replace_job_tags: Dict[str, Any]
        """
        payload = {"jobs": replace_job_tags}
        response = requests.put(f"{self.api_url}/jobs", headers=self.header, json=payload)

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        return None

    def get_job_certificates(self, job_uid: UUID, and_tags: Optional[str] = None, or_tags: Optional[str] = None,
                             mapper: Callable[[Dict[str, Any]], T] = get_paginated_mapper(certificate_mapper),
                             **pagination: Dict[str, Any]) -> T:
        """
        Retrieve all certificates issued in a specific Job, or filter by tags.

        More information on tags on the `VDX Core API <https://docs.vizidox.com/#tags>`__ official documentation.

        Results are paginated, and the pagination parameters should be provided as keyword arguments.

        For more information on the possible parameters, check the
        `VDX Core API <https://docs.vizidox.com/#pagination>`__ official documentation.

        :param job_uid: UID of the job
        :type job_uid: :class:`uuid.UUID`

        :param and_tags: Filter Certificates issued from credentials that contain all the given tags
        :type and_tags: List[str], optional

        :param or_tags: Filter Certificates issued from credentials that contain at least one of the given tags
        :type or_tags: List[str], optional

        :param mapper: Optional mapper to change the format of the endpoint response
        :type mapper: :class:`typing.Callable`

        :param pagination: Keyword arguments for pagination
        :type pagination: Dict[str, Any]

        :return: The result of the endpoint call
        :rtype: :class:`T`
        """
        params = nndict(and_tags=and_tags, or_tags=or_tags)
        params = {**params, **nndict(pagination)}
        response = requests.get(f"{self.api_url}/jobs/{job_uid}/certificates", headers=self.header, params=params)

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        return mapper(response.json()["result"])

    def get_job_credentials(self, job_uid: UUID, and_tags: Optional[str] = None, or_tags: Optional[str] = None,
                            mapper: Callable[[Dict[str, Any]], T] = get_paginated_mapper(credential_mapper),
                            **pagination: Dict[str, Any]) -> Optional[T]:
        """
        Retrieve all credentials issued in a specific Job, or filter by tags.

        More information on tags on the `VDX Core API <https://docs.vizidox.com/#tags>`__ official documentation.

        Results are paginated, and the pagination parameters should be provided as keyword arguments.

        For more information on the possible parameters, check the
        `VDX Core API <https://docs.vizidox.com/#pagination>`__ official documentation.

        :param job_uid: UID of the job
        :type job_uid: :class:`uuid.UUID`

        :param and_tags: Filter Credentials that contain all the given tags
        :type and_tags: List[str], optional

        :param or_tags: Filter Credentials that contain at least one of the given tags
        :type or_tags: List[str], optional

        :param mapper: Optional mapper to change the format of the endpoint response
        :type mapper: :class:`typing.Callable`

        :param pagination: Keyword arguments for pagination
        :type pagination: Dict[str, Any]

        :return: The result of the endpoint call
        :rtype: :class:`T`
        """
        params = nndict(and_tags=and_tags, or_tags=or_tags)
        params = {**params, **nndict(pagination)}
        response = requests.get(f"{self.api_url}/jobs/{job_uid}/credentials", headers=self.header, params=params)

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        return mapper(response.json()["result"])

    def get_certificates(self, mapper: Callable[[Dict[str, Any]], T] = get_paginated_mapper(certificate_mapper), *,
                         job_uid: Optional[UUID] = None, cred_uid: Optional[UUID] = None, uid: Optional[UUID] = None,
                         start_date: Optional[datetime] = None, end_date: Optional[datetime] = None,
                         and_credential_tags: Optional[str] = None, or_credential_tags: Optional[str] = None,
                         and_job_tags: Optional[str] = None, or_job_tags: Optional[str] = None,
                         verification_status: Optional[str] = None, **pagination: Dict[str, Any]) -> T:
        """
        Retrieve all partner certificates, or filter by job, credential, uid,
        issued date (start_date < issued_date < end_date), and credential or job tags.

        More information on tags on the `VDX Core API <https://docs.vizidox.com/#tags>`__ official documentation.

        Results are paginated, and the pagination parameters should be provided as keyword arguments.

        For more information on the possible parameters, check the
        `VDX Core API <https://docs.vizidox.com/#pagination>`__ official documentation.

        :param mapper: Optional mapper to change the format of the endpoint response
        :type mapper: :class:`typing.Callable`

        :param job_uid: Job UID to filter by
        :type job_uid: :class:`uuid.UUID`, optional

        :param cred_uid: Credential UID to filter by
        :type uid: :class:`uuid.UUID`, optional

        :param uid: Certificate UID to filter by
        :type uid: :class:`uuid.UUID`, optional

        :param start_date: Filter by Certificates issued after the given start_date
        :type start_date: :class:`datetime.datetime`, optional

        :param end_date: Filter by Certificates issued before the given end_date
        :type end_date: :class:`datetime.datetime`, optional

        :param and_credential_tags: Filter Certificates of Credentials that contain all the given tags
        :type and_credential_tags: List[str], optional

        :param or_credential_tags: Filter Certificates of Credentials that contain at least one of the given tags
        :type or_credential_tags: List[str], optional

        :param and_job_tags: Filter Certificates issued on Jobs that contain all the given tags
        :type and_job_tags: List[str], optional

        :param or_job_tags: Filter Certificates issued on Jobs that contain at least one of the given tags
        :type or_job_tags: List[str], optional

        :param verification_status: Filter Certificates in the given verification status
        :type verification_status: str, optional

        :param pagination: Keyword arguments for pagination
        :type pagination: Dict[str, Any]

        :return: The result of the endpoint call
        :rtype: :class:`T`
        """
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
        response = requests.get(f"{self.api_url}/certificates", headers=self.header, params=params)

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        return mapper(response.json()["result"])

    def download_certificate(self, cert_uid: UUID) -> io.BytesIO:
        """
        Downloads the JSON proof file for the Certificate, containing all relevant Blockchain details as well
        as the metadata of the corresponding issued credential.

        :param cert_uid: UUID of the certificate to download
        :type cert_uid: :class:`uuid.UUID`

        :return: The result of the endpoint call
        :rtype: :class:`io.BytesIO`
        """
        response = requests.get(f"{self.api_url}/certificates/{cert_uid}/download",headers=self.header)

        status = HTTPStatus(response.status_code)

        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        return io.BytesIO(response.content)

    def verify_by_uid(self, cert_uid: UUID,
                      mapper: Callable[[Dict[str, Any]], T] = verification_mapper) -> T:
        """
        Verify a certificate via its UID.

        :param cert_uid: UUID of the certificate to verify
        :type cert_uid: :class:`uuid.UUID`

        :param mapper: Optional mapper to change the format of the endpoint response
        :type mapper: :class:`typing.Callable`

        :return: The result of the endpoint call
        :rtype: :class:`T`
        """
        response = requests.get(f"{self.api_url}/verify/{cert_uid}", headers=self.header)

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        return mapper(response.json()["result"])

    def verify_by_certificate(self, filename: str, file_stream: BinaryIO, file_content_type: str,
                              mapper: Callable[[Dict[str, Any]], T] = verification_mapper) -> T:
        """
        Verify a certificate via its proof file.

        :param filename: Name of the file
        :type filename: str

        :param file_stream: Certificate proof file stream
        :type file_stream: BinaryIO

        :param file_content_type: Content type of the file
        :type file_content_type: str

        :param mapper: Optional mapper to change the format of the endpoint response
        :type mapper: :class:`typing.Callable`

        :return: The result of the endpoint call
        :rtype: :class:`T`
        """
        file_stream.seek(0)
        payload = {"file": (filename, file_stream, file_content_type)}

        response = requests.post(f"{self.api_url}/verify/upload/certificate", headers=self.header, files=payload)

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        return mapper(response.json()["result"])

    def verify_by_file(self, filename: str, file_stream: BinaryIO, file_content_type: str,
                       mapper: Callable[[Dict[str, Any]], T] = get_paginated_mapper(verification_mapper),
                       **pagination: Dict[str, Any]) -> T:
        """
        Verify a certificate via the credential file.
        Results are paginated, and the pagination parameters should be provided as keyword arguments.

        For more information on the possible parameters, check the
        `VDX Core API <https://docs.vizidox.com/#pagination>`__ official documentation.

        :param filename: Name of the file
        :type filename: str

        :param file_stream: Certificate file stream
        :type file_stream: BinaryIO

        :param file_content_type: Content type of the file
        :type file_content_type: str

        :param mapper: Optional mapper to change the format of the endpoint response
        :type mapper: :class:`typing.Callable`

        :param pagination: Keyword argument containing the pagination parameters
        :type pagination: Dict[str, Any]

        :return: The result of the endpoint call
        :rtype: :class:`T`
        """
        payload = {"file": (filename, file_stream, file_content_type)}
        params = {**nndict(pagination)}

        response = requests.post(f"{self.api_url}/verify/upload/file", headers=self.header, files=payload, params=params)

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        return mapper(response.json()["result"])

    def verify_by_credential_uid(self, cred_uid: UUID,
                                 mapper: Callable[[Dict[str, Any]], T] = get_paginated_mapper(verification_mapper),
                                 **pagination: Dict[str, Any]) -> T:
        """
        Verify certificates via their credential UID.
        Results are paginated, and the pagination parameters should be provided as keyword arguments.

        For more information on the possible parameters, check the
        `VDX Core API <https://docs.vizidox.com/#pagination>`__ official documentation.

        :param cred_uid: UUID of the credential
        :type cred_uid: :class:`uuid.UUID`

        :param mapper: Optional mapper to change the format of the endpoint response
        :type mapper: :class:`typing.Callable`

        :param pagination: Keyword argument containing the pagination parameters
        :type pagination: Dict[str, Any]

        :return: The result of the endpoint call
        :rtype: :class:`T`
        """
        params = {**nndict(pagination)}
        response = requests.get(f"{self.api_url}/verify/credential/{cred_uid}", headers=self.header, params=params)

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        return mapper(response.json()["result"])

    def revoke_certificate(self, cert_uid: UUID) -> datetime:
        """
        Revokes a certificate via its UID, making it no longer valid.

        :param cert_uid: UID of the certificate to be revoked
        :type cert_uid: :class:`uuid.UUID`

        :return: The date the certificate was revoked at
        :rtype: :class:`datetime.datetime`
        """
        response = requests.post(f"{self.api_url}/certificates/{cert_uid}/revoke", headers=self.header)

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        return datetime_from_string(response.json()["result"])

    def revoke_certificate_by_credential(self, cred_uid: UUID, engine: str) -> datetime:
        """
        Revokes a certificate via the credentials UID and for a specific engine, making it no longer valid.

        :param cred_uid: UID of the credential to be revoked
        :type cred_uid: :class:`uuid.UUID`

        :param engine: Blockchain engine to revoke the credential on
        :type engine: str

        :return: The date the certificate was revoked at
        :rtype: :class:`datetime.datetime`
        """
        response = requests.post(f"{self.api_url}/credentials/{cred_uid}/revoke/{engine}", headers=self.header)

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        return datetime_from_string(response.json()["result"])
