from typing import List

from vdx_helper.typing import Json
from vdx_helper.models import EnginePermissionsView, FileView


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
