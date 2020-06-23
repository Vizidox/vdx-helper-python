from typing import List, TypeVar, Callable

from vdx_helper.typing import Json
from vdx_helper.models import EnginePermissionsView, FileView, PaginatedView

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
    return FileView(**json)
