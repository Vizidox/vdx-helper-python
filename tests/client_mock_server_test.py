import io
from unittest.mock import patch
from uuid import UUID

from unittest import TestCase
from testcontainers.compose import DockerCompose
from os import path

from tests.custom_mappers_mock_tests import custom_permissions_mapper, custom_credential_mapper, custom_job_mapper, \
    custom_verification_mapper, custom_certificate_mapper
from vdx_helper import VDXHelper
from vdx_helper.mappers import get_paginated_mapper


def inside_docker() -> bool:
    """
    Returns true if we are running inside a docker container

    https://github.com/docker/docker/blob/a9fa38b1edf30b23cae3eade0be48b3d4b1de14b/daemon/initlayer/setup_unix.go#L25
    """
    return path.isfile('/.dockerenv')


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

    @patch('vdx_helper.vdx_helper.VDXHelper._get_token_string')
    def test_verify_by_file(self, _get_token_string):
        vdx_helper = self.get_vdx_helper()
        _get_token_string.return_value = "vizidox-authorization"

        filename = "file_name"
        file_content_type = "text/plain"
        memory_file = io.BytesIO()
        # todo fix this
        verification_response = vdx_helper.verify_by_file(filename=filename, file_stream=memory_file,
                                                          file_content_type=file_content_type,
                                                          mapper=custom_verification_mapper)
        assert verification_response is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._get_token_string')
    def test_verify_by_credential_uid(self, _get_token_string):
        vdx_helper = self.get_vdx_helper()
        _get_token_string.return_value = "vizidox-authorization"

        cred_id = UUID('123e4567-e89b-12d3-a456-426655440000')
        # todo fix this
        verification_response = vdx_helper.verify_by_credential_uid(cred_uid=cred_id, mapper=custom_verification_mapper)
        assert verification_response is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._get_token_string')
    def test_verify_by_certificate_uid(self, _get_token_string):
        vdx_helper = self.get_vdx_helper()
        _get_token_string.return_value = "vizidox-authorization"
        cert_uid = UUID('123e4567-e89b-12d3-a456-426655440000')
        # todo fix this
        verification_response = vdx_helper.verify_by_uid(cert_uid=cert_uid, mapper=custom_verification_mapper)
        assert verification_response is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._get_token_string')
    def test_get_certificates(self, _get_token_string):
        _get_token_string.return_value = "vizidox-authorization"
        vdx_helper = self.get_vdx_helper()

        certificates = vdx_helper.get_certificates(mapper=get_paginated_mapper(custom_certificate_mapper))
        assert certificates is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._get_token_string')
    def test_revoke_certificate(self, _get_token_string):
        vdx_helper = self.get_vdx_helper()
        _get_token_string.return_value = "vizidox-authorization"
        cert_uid = UUID("939a9ccb-ddf9-424c-94eb-91898455a968")
        vdx_helper.revoke_certificate(cert_uid=cert_uid)

    @patch('vdx_helper.vdx_helper.VDXHelper._get_token_string')
    def test_download_certificate(self, _get_token_string):
        vdx_helper = self.get_vdx_helper()
        _get_token_string.return_value = "vizidox-authorization"
        cert_uid = UUID("939a9ccb-ddf9-424c-94eb-91898455a968")

        certificate = vdx_helper.download_certificate(cert_uid=cert_uid)
        assert certificate is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._get_token_string')
    def test_get_job_certificates(self, _get_token_string):
        vdx_helper = self.get_vdx_helper()
        _get_token_string.return_value = "vizidox-authorization"
        job_uid = UUID("939a9ccb-ddf9-424c-94eb-91898455a968")
        certificates = vdx_helper.get_job_certificates(job_uid=job_uid, pagination=None,
                                                       mapper=get_paginated_mapper(custom_certificate_mapper))
        assert certificates is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._get_token_string')
    def test_get_job_credentials(self, _get_token_string):
        _get_token_string.return_value = "vizidox-authorization"
        vdx_helper = self.get_vdx_helper()
        job_uid = UUID("939a9ccb-ddf9-424c-94eb-91898455a968")

        credentials = vdx_helper.get_job_credentials(job_uid=job_uid, mapper=get_paginated_mapper(
            custom_credential_mapper))
        assert credentials is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._get_token_string')
    def test_schedule_credentials(self, _get_token_string):
        vdx_helper = self.get_vdx_helper()
        _get_token_string.return_value = "vizidox-authorization"
        engine = 'dogecoin'
        credentials = ["939a9ccb-ddf9-424c-94eb-91898455a968", "39c7ddcd-f480-48e5-8056-fabf84e7f859"]

        job = vdx_helper.schedule_credentials(engine=engine, credentials=credentials, mapper=custom_job_mapper)
        assert job is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._get_token_string')
    def test_get_file_attributes(self, _get_token_string):
        vdx_helper = self.get_vdx_helper()
        _get_token_string.return_value = "vizidox-authorization"
        file_id = "hello_this_is_file_id"
        file = vdx_helper.get_file_attributes(core_id=file_id)
        assert file is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._get_token_string')
    def test_update_job_tags(self, _get_token_string):
        vdx_helper = self.get_vdx_helper()
        _get_token_string.return_value = "vizidox-authorization"
        updated_job_tags = [{"tag": "tag"}]
        vdx_helper.update_job_tags(updated_job_tags=updated_job_tags)

    @patch('vdx_helper.vdx_helper.VDXHelper._get_token_string')
    def test_replace_job_tags(self, _get_token_string):
        vdx_helper = self.get_vdx_helper()
        _get_token_string.return_value = "vizidox-authorization"
        replace_job_tags = [{"tag": "tag"}]
        vdx_helper.replace_job_tags(replace_job_tags=replace_job_tags)

    @patch('vdx_helper.vdx_helper.VDXHelper._get_token_string')
    def test_update_credential_tags(self, _get_token_string):
        vdx_helper = self.get_vdx_helper()
        _get_token_string.return_value = "vizidox-authorization"
        updated_credential_tags = [
            {
                "credential_uid": "123e4567-e89b-12d3-a456-426655440000",
                "tags": [
                    "tagA",
                    "tagB",
                    "tagC"
                ]
            }
        ]
        vdx_helper.update_credential_tags(updated_credential_tags=updated_credential_tags)

    @patch('vdx_helper.vdx_helper.VDXHelper._get_token_string')
    def test_replace_credential_tags(self, _get_token_string):
        vdx_helper = self.get_vdx_helper()
        _get_token_string.return_value = "vizidox-authorization"
        replace_credential_tags = [
            {
                "credential_uid": "123e4567-e89b-12d3-a456-426655440000",
                "tags": [
                    "tagA",
                    "tagB",
                    "tagC"
                ]
            }
        ]
        vdx_helper.replace_credential_tags(replace_credential_tags=replace_credential_tags)

    @patch('vdx_helper.vdx_helper.VDXHelper._get_token_string')
    def test_delete_credential_tag(self, _get_token_string):
        vdx_helper = self.get_vdx_helper()
        _get_token_string.return_value = "vizidox-authorization"
        credential_tag = "tagA"
        cred_uid = UUID("d39fca4b-5f7a-4e7d-8c1e-665988de808e")

        vdx_helper.delete_credential_tag(cred_uid=cred_uid, tag=credential_tag)
