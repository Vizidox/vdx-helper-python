from datetime import datetime
import io
from typing import List
from unittest.mock import patch
from uuid import UUID

from unittest import TestCase
from testcontainers.compose import DockerCompose
from os import path

from vdx_helper import VDXHelper
from vdx_helper.mappers import credential_mapper, file_mapper, get_paginated_mapper, partner_mapper
from vdx_helper.models import EnginePermissionsView, CredentialView, JobView, JobStatus
from vdx_helper.typing import Json


def inside_docker() -> bool:
    """
    Returns true if we are running inside a docker container

    https://github.com/docker/docker/blob/a9fa38b1edf30b23cae3eade0be48b3d4b1de14b/daemon/initlayer/setup_unix.go#L25
    """
    return path.isfile('/.dockerenv')


def custom_permissions_mapper(_json: Json) -> List[EnginePermissionsView]:
    permission_views = list()
    for json_permission in _json:
        permission = EnginePermissionsView(
            name=json_permission['name'],
            is_allowed=json_permission['is_allowed'],
            # for some reason prism generates "python valid booleans" so no need for conversion
            show_prices=json_permission["show_prices"]
        )
        permission_views.append(permission)
    return permission_views


def custom_credential_mapper(json: Json) -> CredentialView:
    return CredentialView(
        uid=UUID(json["uid"]),
        title=json["title"],
        metadata=json["metadata"],
        files=[file_mapper(file) for file in json["files"]],
        credentials=[credential_mapper(credential) if 'credential' in json["credentials"] else [] for credential in
                     json["credentials"]],
        upload_date=datetime.fromisoformat(json["upload_date"]),
        tags=json["tags"],
        expiry_date=datetime.fromisoformat(json["expiry_date"])
    )


def custom_job_mapper(json: Json) -> JobView:
    return JobView(
        uid=UUID(json["uid"]),
        partner=partner_mapper(json["partner"]),
        chain=json["chain"],
        tags=json["tags"],
        status=JobStatus[json["status"]],
        created_date=datetime.fromisoformat(json["created_date"]),
        start_date=datetime.fromisoformat(json["start_date"]) if "start_date" in json else None,
        issued_date=datetime.fromisoformat(json["issued_date"]) if "issued_date" in json else None,
        finished_date=datetime.fromisoformat(json["finished_date"]) if "finished_date" in json else None,
        failed_date=datetime.fromisoformat(json["failed_date"]) if "failed_date" in json else None,
        scheduled_date=datetime.fromisoformat(json["scheduled_date"]) if "scheduled_date" in json else None
    )


class ClientMockServerTest(TestCase):
    mock_server = None if inside_docker() else DockerCompose('./')
    mock_host = 'http://prism:4030' if inside_docker() else 'http://localhost:4030'
    mock_endpoint = mock_host + '/api'

    def setUp(self) -> None:
        self.client = VDXHelper(self.mock_endpoint, 'http://vizidox-keycloak.com', 'core-api-key', 'core-api-client-id')

        self.keycloak_url = "http://vizidox-keycloak.com"
        self.core_api_key = 'core_api_key'
        self.core_api_client_id = 'core_api_client_id'
        self.default_current_time = 300
        self.default_json_value = {'name': 'vizidox', 'value': 123}

    def get_vdx_helper(self):
        vdx_helper = VDXHelper(url=self.mock_endpoint, keycloak_url=self.keycloak_url,
                               core_api_key=self.core_api_key, core_api_client_id=self.core_api_client_id)
        return vdx_helper

    @classmethod
    def setUpClass(cls) -> None:
        if cls.mock_server is not None:
            cls.mock_server.start()
            cls.mock_server.wait_for(cls.mock_endpoint)

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.mock_server is not None:
            cls.mock_server.stop()

    @patch('vdx_helper.vdx_helper.VDXHelper._get_token_string')
    def test_get_partner_permissions(self, _get_token_string) -> None:
        _get_token_string.return_value = "vizidox-authorization"
        vdx_helper = self.get_vdx_helper()
        permissions = vdx_helper.get_partner_permissions(mapper=custom_permissions_mapper)
        assert permissions is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._get_token_string')
    def test_get_engine_cost(self, _get_token_string) -> None:
        _get_token_string.return_value = "vizidox-authorization"
        vdx_helper = self.get_vdx_helper()
        # todo this endpoint is not available in the core-api
        # permissions = vdx_helper.get_engine_cost('dogecoin', 10)
        # assert permissions is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._get_token_string')
    def test_get_files(self, _get_token_string) -> None:
        _get_token_string.return_value = "vizidox-authorization"
        vdx_helper = self.get_vdx_helper()
        files = vdx_helper.get_files()
        assert files is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._get_token_string')
    def test_upload_file(self, _get_token_string):
        _get_token_string.return_value = "vizidox-authorization"
        vdx_helper = self.get_vdx_helper()
        # file
        filename = "hello_this_is_filename"
        content_type = "text/plain"

        # todo file mock
        memory_file = io.BytesIO()
        file_summary = vdx_helper.upload_file(filename, memory_file, content_type)
        assert file_summary is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._get_token_string')
    def test_update_file_attributes(self, _get_token_string):
        _get_token_string.return_value = "vizidox-authorization"
        vdx_helper = self.get_vdx_helper()
        filename = 'new_name'
        core_id = "core_id"

        vdx_helper.update_file_attributes(core_id=core_id, filename=filename)

    @patch('vdx_helper.vdx_helper.VDXHelper._get_token_string')
    def test_get_credentials(self, _get_token_string):
        _get_token_string.return_value = "vizidox-authorization"
        vdx_helper = self.get_vdx_helper()

        credentials = vdx_helper.get_credentials(mapper=get_paginated_mapper(custom_credential_mapper))
        assert credentials is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._get_token_string')
    def test_get_credential(self, _get_token_string):
        _get_token_string.return_value = "vizidox-authorization"
        vdx_helper = self.get_vdx_helper()
        cred_uid = '189e4e5c-833d-430b-9baa-5230841d997f'
        credential = vdx_helper.get_credential(UUID(cred_uid), mapper=custom_credential_mapper)
        assert credential is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._get_token_string')
    def test_create_credential(self, _get_token_string):
        _get_token_string.return_value = "vizidox-authorization"
        vdx_helper = self.get_vdx_helper()

        title = 'title'
        metadata = {}
        tags = ["tagA", "tagB", "tagC"]
        core_ids = ['939a9ccb-ddf9-424c-94eb-91898455a968']
        cred_ids = ['123e4567-e89b-12d3-a456-426655440000']
        expiry_date = "2020-02-11T15:34:05.814607+00:00"

        credential = vdx_helper.create_credential(title=title, tags=tags, metadata=metadata, core_ids=core_ids,
                                                  cred_ids=cred_ids, expiry_date=expiry_date, mapper=custom_credential_mapper)
        assert credential is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._get_token_string')
    def test_issue_job(self, _get_token_string):
        _get_token_string.return_value = "vizidox-authorization"
        vdx_helper = self.get_vdx_helper()
        engine = 'dogecoin'

        job = vdx_helper.issue_job(engine=engine, mapper=custom_job_mapper)
        assert job is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._get_token_string')
    def test_get_job(self, _get_token_string):
        _get_token_string.return_value = "vizidox-authorization"
        vdx_helper = self.get_vdx_helper()
        job_uid = UUID('939a9ccb-ddf9-424c-94eb-91898455a968')
        job = vdx_helper.get_job(job_uid, mapper=custom_job_mapper)
        assert job is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._get_token_string')
    def test_get_jobs(self, _get_token_string):
        _get_token_string.return_value = "vizidox-authorization"
        vdx_helper = self.get_vdx_helper()
        jobs = vdx_helper.get_jobs(mapper=get_paginated_mapper(custom_job_mapper))
        assert jobs is not None