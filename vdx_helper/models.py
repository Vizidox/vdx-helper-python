from datetime import datetime
from enum import Enum
from typing import NamedTuple, Optional, List, Mapping, Generic, TypeVar
from uuid import UUID

T = TypeVar('T')


class EnginePermissionsView(NamedTuple):
    """
    An Engine Permission View to be returned by the API
    ---
    type: array
    items:
      type: object
      title: EnginePermissions
      required:
      - name
      - is_allowed
      - show_prices
      properties:
        name:
          type: string
          description: 'The blockchain engine name'
        is_allowed:
          type: boolean
          description: 'The partner''s access to issuing on the blockchain'
        show_prices:
          type: boolean
          description: 'The partner''s access to the currency issuing price'
    """
    name: str
    is_allowed: bool
    show_prices: bool

    def __eq__(self, obj: 'EnginePermissionsView'):
        return isinstance(obj, EnginePermissionsView) \
               and obj.name == self.name \
               and obj.is_allowed == self.is_allowed \
               and obj.show_prices == self.show_prices


class PaginatedView(NamedTuple, Generic[T]):
    """
    A Paginated View to be returned by the API
    ---
    type: object
    title: Paginated
    properties:
      page:
        type: integer
        description: 'The current page'
      total_pages:
        type: integer
        description: 'Total number of pages'
      per_page:
        type: integer
        description: 'The number of items per page'
      total_items:
        type: integer
        description: 'The total number of items obtained from the query'
      items:
        type: array
        description: 'List of items'
        items:
          type: object
    """
    page: int
    total_pages: int
    per_page: int
    total_items: int
    items: List[T]

    def __eq__(self, obj: 'PaginatedView'):
        return isinstance(obj, PaginatedView) \
               and obj.page == self.page \
               and obj.total_pages == self.total_pages \
               and obj.per_page == self.per_page \
               and obj.total_items == self.total_items \
               and all([first == second for first, second in zip(obj.items, self.items)])


class PartnerView(NamedTuple):
    """
    A Partner View to be returned by the API
    ---
    type: object
    description: 'The issuing partner'
    required:
    - id
    - name
    properties:
      id:
        type: string
        description: 'The partner id'
      name:
        type: string
        description: 'The partner name'
    """
    id: str
    name: str

    def __eq__(self, obj: 'PartnerView'):
        return isinstance(obj, PartnerView) and obj.id == self.id and obj.name == self.name


class FileView(NamedTuple):
    """
    A File View to be returned by the API
    ---
    required:
    - file_hash
    properties:
      file_hash:
        type: string
        description: 'The file hash'
      file_type:
        type: string
        description: 'The type of the file'
    """
    file_hash: str
    file_type: Optional[str]

    def __eq__(self, obj: 'FileView'):
        return isinstance(obj, FileView) \
               and obj.file_hash == self.file_hash \
               and obj.file_type == self.file_type


class CredentialView(NamedTuple):
    """
    A Credential View to be returned by the API
    ---
    type: object
    required:
    - uid
    - title
    - metadata
    - files
    - credentials
    - upload_date
    - tags
    properties:
      uid:
        type: string
        title: uuid
        example: 123e4567-e89b-12d3-a456-426655440000
        description: 'The credential uid'
      title:
        type: string
        description: 'The credential title'
      metadata:
        type: object
        additionalProperties: {}
        description: 'Additional data in the credential'
      files:
        type: array
        title: Files
        $ref: '#/definitions/File'
        items:
          type: object
      files:
        type: array
        title: Files
        $ref: '#/definitions/File'
        items:
          type: object
      upload_date:
        type: number
        title: datetime
        example: '2020-02-11T15:34:05.811954+00:00'
        description: 'The credential date of creation'
      tags:
        type: array
        description: 'A list of tags to identify the job'
        example: ['tagA', 'tagB', 'tagC']
        items:
          type: string
      expiry_date:
        type: number
        title: datetime
        example: '2020-02-11T15:34:05.813229+00:00'
        description: 'The date of expiry, if it was selected'
    """
    uid: UUID
    title: str
    metadata: dict
    files: List[FileView]
    credentials: List['CredentialView']
    upload_date: datetime
    tags: List[str]
    expiry_date: Optional[datetime]

    def __eq__(self, obj: 'CredentialView'):
        return isinstance(obj, CredentialView) \
               and obj.uid == self.uid \
               and obj.title == self.title \
               and obj.metadata == self.metadata \
               and all([first == second for first, second in zip(obj.files, self.files)]) \
               and all([first == second for first, second in zip(obj.credentials, self.credentials)]) \
               and obj.upload_date == self.upload_date \
               and obj.tags == self.tags \
               and obj.expiry_date == self.expiry_date


class ClaimView(NamedTuple):
    """
    A Claim View to be returned by the API
    A Claim has all data directly related to the issuing Certificate
    ---
    type: object
    required:
    - uid
    - partner
    - credential
    - issued_date
    - signature
    properties:
      uid:
        type: string
        title: uuid
        example: 123e4567-e89b-12d3-a456-426655440000
        description: 'The certificate uid'
      partner:
        $ref: '#/definitions/Partner'
      credential:
        $ref: '#/definitions/Credential'
      issued_date:
        type: number
        title: datetime
        example: '2020-02-11T15:34:05.813217+00:00'
        description: 'The issuing date of the certificate'
      signature:
        type: string
        description: 'The partners signature on the certificate'

    """
    uid: UUID
    partner: PartnerView
    credential: CredentialView
    issued_date: datetime
    signature: str

    def __eq__(self, obj: 'ClaimView'):
        return isinstance(obj, ClaimView) and obj.uid == self.uid


class VerificationStatus(Enum):
    """
    A representation of all possible verification status
    """
    ok = 'ok'
    pending = 'pending'
    expired = 'expired'
    revoked = 'revoked'
    failed = 'failed'
    error = 'error'


class VerificationReport(NamedTuple):
    """
    A Verification Report View to be returned by the API
    ---
    type: object
    title: VerificationReport
    description: 'The result of the latest verification performed on the certificate'
    required:
    - status
    - timestamp
    properties:
      status:
        type: string
        description: 'The status of the full verification'
        enum:
        - ok
        - pending
        - expired
        - revoked
        - failed
        - error
      timestamp:
        type: number
        title: datetime
        description: 'The date of verification'
        example: '2020-02-11T15:34:05.813289+00:00'
    """
    status: VerificationStatus
    timestamp: datetime


class StepStatus(Enum):
    """
    A representation of all status of a verification step
    """
    not_started = 'not_started'
    passed = 'passed'
    pending = 'pending'
    failed = 'failed'
    error = 'error'


class VerificationStepResult(NamedTuple):
    """
    Represents the result of one verification step
    ---
    required:
    - name
    - description
    - status
    properties:
      name:
        type: string
        description: 'The name of the verification step'
      description:
        type: object
        description: 'A description of the result of the verification step'
        additionalProperties:
          type:
            type: string
      status:
        type: string
        description: 'The status of the result'
        enum:
        - not_started
        - passed
        - pending
        - failed
        - error
    """
    name: str
    description: Mapping[str, Optional[str]]
    status: StepStatus


class VerificationResponseView(NamedTuple):
    """
     A Verification Response View to be returned by the API
    ---
    type: object
    title: VerificationResponse
    required:
    - verification
    properties:
      verification:
        type: array
        items:
          type: object
          description: 'The combined result of all verification steps'
          $ref: '#/definitions/VerificationStep'
      result:
        type: object
        description: The final result of the verification
        $ref: '#/definitions/VerificationReport'
    """
    verification: List[VerificationStepResult]
    result: VerificationReport


class CertificateView(NamedTuple):
    """
    A Certificate View to be returned by the API
    ---
    type: object
    title: Certificate
    required:
    - certificate
    properties:
      certificate:
        $ref: '#/definitions/Claim'
      last_verification:
        $ref: '#/definitions/VerificationReport'
    """
    certificate: ClaimView
    last_verification: Optional[VerificationReport]


class CurrencyAmountView(NamedTuple):
    """
    A Currency Amount View to be returned by the API

    """
    amount: float
    currency: str


class JobStatus(Enum):
    """
    A representation of all possible status of a Job
    """
    failed = 'failed'
    started = 'started'
    unconfirmed = 'unconfirmed'
    pending = 'pending'
    finished = 'finished'
    scheduled = 'scheduled'


class JobView(NamedTuple):
    """
    A Job View to be returned by the API
    ---
    required:
    - uid
    - partner
    - chain
    - tags
    - status
    - created_date
    properties:
      uid:
        type: string
        title: uuid
        example: 123e4567-e89b-12d3-a456-426655440000
        description: 'The job uid'
      partner:
        $ref: '#/definitions/Partner'
      chain:
        type: string
        description: 'The blockchain the Job was issued on'
      tags:
        type: array
        description: 'A list of tags to identify the job'
        items:
          type: string
      status:
        type: string
        description: 'The current status of the Job'
        enum:
        - failed
        - started
        - awaiting_confirmations
        - ready
      start_date:
        type: number
        title: datetime
        example: '2020-02-11T15:34:05.814703+00:00'
        description: 'The date the Job was started'
      issued_date:
        type: number
        title: datetime
        example: '2020-02-11T15:34:05.814719+00:00'
        description: 'The date of issuing, if successful'
      finished_date:
        type: number
        title: datetime
        example: '2020-02-11T15:34:05.814731+00:00'
        description: 'The date of confirmation, if successful'
      failed_date:
        type: number
        title: datetime
        example: '2020-02-11T15:34:05.814743+00:00'
        description: 'The date of failure, if the issuing failed'
      created_date:
        type: number
        title: datetime
        example: '2020-02-11T15:34:05.814743+00:00'
        description: 'The date on which the job was created'
      scheduled_date:
        type: number
        title: datetime
        example: '2020-02-11T15:34:05.814743+00:00'
        description: 'The date on which the job is scheduled to be issued'

    """
    uid: UUID
    partner: PartnerView
    chain: str
    tags: List[str]
    status: JobStatus
    created_date: datetime
    scheduled_date: Optional[datetime] = None
    start_date: Optional[datetime] = None
    issued_date: Optional[datetime] = None
    finished_date: Optional[datetime] = None
    failed_date: Optional[datetime] = None
