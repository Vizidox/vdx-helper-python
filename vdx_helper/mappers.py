from datetime import datetime
from typing import List, TypeVar, Callable
from uuid import UUID

from vdx_helper.typing import Json
from vdx_helper.models import EnginePermissionsView, FileView, PaginatedView, CredentialView

T = TypeVar('T')


def get_paginated_mapper(mapper: Callable[[Json], T]) -> Callable[[Json], 'PaginatedView[T]']:
    def paginated_mapper(json: Json) -> 'PaginatedView[T]':
        paginated_view = PaginatedView(
            page=json["page"],
            total_pages=json["total_pages"],
            per_page=json["per_page"],
            total_items=json["total_items"],
            items=[mapper(json_item) for json_item in json["items"]]
        )
        return paginated_view

    return paginated_mapper


def permissions_mapper(json: Json) -> List[EnginePermissionsView]:
    permission_views = list()
    for json_permission in json:
        permission = EnginePermissionsView(
            **json_permission
        )
        permission_views.append(permission)
    return permission_views


def file_mapper(json: Json) -> FileView:
    return FileView(
        id=json["id"],
        file_hash=json["file_hash"],
        filename=json["filename"],
        uploaded=datetime.fromisoformat(json["uploaded"]),
        file_type=json["file_type"]
    )


def credential_mapper(json: Json) -> CredentialView:
    return CredentialView(
        uid=UUID(),
        title=json["title"],
        metadata=json["metadata"],
        file=file_mapper(json["file"]) if "file" in json else None,
        upload_date=datetime.fromisoformat(json["upload_date"]),
        tags=json["tags"],
        expiry_date=datetime.fromisoformat(json["expiry_date"])
    )
