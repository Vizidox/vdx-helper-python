from vdx_helper.typing import Json
from vdx_helper.models import EnginePermissionsView


def permissions_mapper(json: Json):
    permission_views = list()
    for json_permission in json:
        permission = EnginePermissionsView(
            **json_permission
        )
        permission_views.append(permission)
    return permission_views