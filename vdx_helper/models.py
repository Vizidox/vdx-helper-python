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


class FileView(NamedTuple):
    """
    A File View to be returned by the API
    ---
    required:
    - id
    - file_hash
    - filename
    - uploaded
    properties:
      id:
        type: string
        description: 'The id of the file'
      file_hash:
        type: string
        description: 'The file hash'
      filename:
        type: string
        description: 'The name of the file'
      uploaded:
        type: number
        title: datetime
        example: '2020-02-11T15:34:05.811915+00:00'
        description: 'The date at which it was uploaded'
      file_type:
        type: string
        description: 'The type of the file'
    """
    id: str
    file_hash: str
    filename: str
    uploaded: datetime
    file_type: Optional[str]


class CredentialView(NamedTuple):
    """
    A Credential View to be returned by the API
    ---
    type: object
    required:
    - uid
    - title
    - metadata
    - file
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
      file:
        type: object
        title: File
        $ref: '#/definitions/File'
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
    file: Optional[FileView]
    upload_date: datetime
    tags: List[str]
    expiry_date: Optional[datetime]


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


class VerificationStatus(Enum):
    """
    A representation of all possible verification status
    """
    ok = 5
    pending = 4
    expired = 3
    revoked = 2
    failed = 1
    error = 0


class StepStatus(Enum):
    """
    A representation of all status of a verification step
    """
    not_started = 0
    passed = 1
    pending = 2
    failed = 3
    error = 4


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
      file:
        description: 'The view of the verified file'
        $ref: '#/definitions/File'
      verification:
        type: array
        items:
          type: object
          description: 'The combined result of all verification steps'
          $ref: '#/definitions/VerificationStep'
    """
    file: Optional[FileView]
    verification: List[VerificationStepResult]


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
    failed = 0
    started = 1
    unconfirmed = 2
    pending = 3
    finished = 4


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
    - start_date
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

    """
    uid: UUID
    partner: PartnerView
    chain: str
    tags: List[str]
    status: JobStatus
    start_date: datetime
    issued_date: Optional[datetime] = None
    finished_date: Optional[datetime] = None
    failed_date: Optional[datetime] = None
