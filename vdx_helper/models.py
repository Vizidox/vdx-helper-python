from datetime import datetime
from typing import NamedTuple, Optional, List, Mapping, Generic, TypeVar, Dict
from uuid import UUID

from vdx_helper.domain import VerificationStatus, StepStatus, JobStatus

T = TypeVar('T')


class Partner(NamedTuple):
    """
    A Partner object returned by the Core API.

    :param id: The partner ID
    :type id: str

    :param name: The name of the partner
    :type name: str
    """
    id: str
    name: str

    def __eq__(self, obj: object) -> bool:
        """
        Overriding of the equals method for simplified comparison between Partner objects.

        :param obj: The other instance of a Partner object
        :type obj: object

        :return: True if the two objects are equal
        :rtype: bool
        """
        return isinstance(obj, Partner) and obj.id == self.id and obj.name == self.name


class File(NamedTuple):
    """
    Object representing a File returned by the Core API.

    :param file_hash: The file's hash
    :type file_hash: str

    :param file_type: The file `MIME type <https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types>`
    :type file_type: str, optional
    """
    file_hash: str
    file_type: Optional[str]

    def __eq__(self, obj: object) -> bool:
        """
        Overriding of the equals method for simplified comparison between File objects.

        :param obj: The other instance of a File object
        :type obj: object

        :return: True if the two objects are equal
        :rtype: bool
        """
        return isinstance(obj, File) \
               and obj.file_hash == self.file_hash \
               and obj.file_type == self.file_type


class Credential(NamedTuple):
    """
    Object representing a Credential returned by the Core API.

    :param uid: The uid of the credential
    :type uid: :class:`uuid.UUID`

    :param title: The credential title
    :type title: str

    :param metadata: Any additional data in the credential
    :type metadata: Dict

    :param files: List of files issued on the credential
    :type files: List[:class:`File`]

    :param credentials: List of credentials associated to the credential
    :type credentials: List[:class:`Credential`]

    :param upload_date: The date the credential was uploaded
    :type upload_date: :class:`datetime.datetime`

    :param tags: List of tags identifying the credential
    :type tags: List[str]

    :param expiry_date: The date the credential expires, if set
    :type expiry_date: :class:`datetime.datetime`, optional
    """
    uid: UUID
    title: str
    metadata: dict
    files: List[File]
    credentials: List['Credential']
    upload_date: datetime
    tags: List[str]
    expiry_date: Optional[datetime]

    def __eq__(self, obj: object) -> bool:
        """
        Overriding of the equals method for simplified comparison between Credential objects.

        :param obj: The other instance of a credential object
        :type obj: object

        :return: True if the two objects are equal
        :rtype: bool
        """
        return (
            isinstance(obj, Credential)
            and obj.uid == self.uid
            and obj.title == self.title
            and obj.metadata == self.metadata
            and all(
                first == second for first, second in zip(obj.files, self.files)
            )
            and all(
                first == second
                for first, second in zip(obj.credentials, self.credentials)
            )
            and obj.upload_date == self.upload_date
            and obj.tags == self.tags
            and obj.expiry_date == self.expiry_date
        )


class Job(NamedTuple):
    """
    Object representing a Certificate returned by the Core API.

    :param uid: uid of the Job
    :type uid: :class:`uuid.UUID`

    :param partner: The partner who issued the job
    :type partner: :class:`Partner`

    :param chain: The Blockchain engine the job was issued on
    :type chain: str

    :param tags: List of tags identifying the credential
    :type tags: List[str]

    :param status: Current status of the job
    :type status: :class:`vdx_helper.JobStatus`

    :param created_date: The date the job was created
    :type created_date: :class:`datetime.datetime`

    :param scheduled_date: The date the job will be issued, if not yet issued
    :type scheduled_date: :class:`datetime.datetime`, optional

    :param start_date: The date the job started issuing
    :type start_date: :class:`datetime.datetime`, optional

    :param issued_date: The date the job was issued
    :type issued_date: :class:`datetime.datetime`, optional

    :param finished_date: The date the job issuing was confirmed on the blockchain
    :type finished_date: :class:`datetime.datetime`, optional

    :param failed_date: The date the job issuing failed, if applicable
    :type failed_date: :class:`datetime.datetime`, optional
    """
    uid: UUID
    partner: Partner
    chain: str
    tags: List[str]
    status: JobStatus
    created_date: datetime
    scheduled_date: Optional[datetime] = None
    start_date: Optional[datetime] = None
    issued_date: Optional[datetime] = None
    finished_date: Optional[datetime] = None
    failed_date: Optional[datetime] = None


class VerificationStepResult(NamedTuple):
    """
    Object representing the result of a step of the verification process.

    :param name: The name of the step
    :type name: str

    :param description: The result of the verification step, containing several fields and values
    :type description: dict

    :param status: The final status of the step
    :type status: :class:`vdx_helper.StepStatus`
    """
    name: str
    description: Mapping[str, Optional[str]]
    status: StepStatus


class VerificationReport(NamedTuple):
    """
    Object representing the final result of the verification of a certificate, not including the individual result of
    each step.

    :param status: The status of the verification
    :type status: :class:`vdx_helper.domain.VerificationStatus`

    :param timestamp: The date of the verification
    :type timestamp: :class:`datetime.datetime`
    """
    status: VerificationStatus
    timestamp: datetime


class VerificationResponse(NamedTuple):
    """
    Object representing the result of a verification returned from the API, including all steps.

    :param verification: The list of all verification steps
    :type verification: Dict[str, :class:`VerificationStepResult`]

    :param result: The result of the verification
    :type result: :class:`VerificationReport`
    """
    verification: Dict[str, VerificationStepResult]
    result: VerificationReport


class Claim(NamedTuple):
    """
    Object representing a Credential returned by the Core API.
    A Claim has all data directly related to the issued Certificate.

    :param uid: The uid of the certificate
    :type uid: :class:`uuid.UUID`

    :param partner: The partner who issued the certificate
    :type partner: :class:`Partner`

    :param credential: The credential that was issued
    :type credential: :class:`Credential`

    :param issued_date: Date of issuing on the Blockchain
    :type issued_date: :class:`datetime.datetime`

    :param signature: Signed content of the credential by the partner's issuing key
    :type signature: str
    """
    uid: UUID
    partner: Partner
    credential: Credential
    issued_date: datetime
    signature: str

    def __eq__(self, obj: object) -> bool:
        """
        Overriding of the equals method for simplified comparison between Claim objects.

        :param obj: The other instance of a claim object
        :type obj: object

        :return: True if the two objects are equal
        :rtype: bool
        """
        return isinstance(obj, Claim) and obj.uid == self.uid


class Certificate(NamedTuple):
    """
    Object representing a Certificate returned by the Core API.

    :param certificate: The details and data of the certificate and respective credential
    :type certificate: :class:`Claim`

    :param revoked_date: The date of revocation, if applicable
    :type revoked_date: :class:`datetime.datetime`, optional

    :param last_verification: The result of the latest verification of the certificate
    :type last_verification: :class:`VerificationReport`
    """
    certificate: Claim
    revoked_date: Optional[datetime]
    last_verification: Optional[VerificationReport]


class PaginatedResponse(NamedTuple, Generic[T]):
    """
    Object representing a paginated response from the API.
    from the API

    :param page: The page the items are from
    :type page: int

    :param total_pages: The total number of pages
    :type total_pages: int

    :param per_page: The number of items returned per page
    :type per_page: int

    :param total_items: The total number of items
    :type total_items: int

    :param items: The list of objects returned by the API
    :type items: List[T]
    """
    page: int
    total_pages: int
    per_page: int
    total_items: int
    items: List[T]

    def __eq__(self, obj: object) -> bool:
        """
        Overriding of the equals method for simplified comparison between Paginated objects.

        :param obj: The other instance of a paginated object
        :type obj: object

        :return: True if the two objects are equal
        :rtype: bool
        """
        return (
                isinstance(obj, PaginatedResponse)
                and obj.page == self.page
                and obj.total_pages == self.total_pages
                and obj.per_page == self.per_page
                and obj.total_items == self.total_items
                and all(first == second for first, second in zip(obj.items, self.items))
        )
