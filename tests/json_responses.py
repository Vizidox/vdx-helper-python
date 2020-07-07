from datetime import datetime
from uuid import UUID

from vdx_helper.models import FileView, EnginePermissionsView, CredentialView, PaginatedView

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

mapped_engine_permissions = [EnginePermissionsView(name="bitcoin", is_allowed=True, show_prices=True),
                             EnginePermissionsView(name="dogecoin", is_allowed=False, show_prices=False)]

file_json = {
    "id": "123",
    "file_hash": "hash",
    "filename": "name",
    "uploaded": "2020-01-01T10:29:28.977178+00:00",
    "file_type": "type"
}

mapped_file = FileView(id="123", file_hash="hash", filename="name",
                       uploaded=datetime.fromisoformat("2020-01-01T10:29:28.977178+00:00"), file_type="type")

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

mapped_paginated_credential = PaginatedView(page=1, total_pages=1, per_page=20, total_items=1, items=[mapped_credential])
