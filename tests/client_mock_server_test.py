from http import HTTPStatus
from os import path
from unittest import TestCase
from unittest.mock import patch, PropertyMock
from uuid import UUID

import requests
from testcontainers.compose import DockerCompose
from tests.custom_mappers_mock_tests import custom_credential_mapper, custom_job_mapper, \
    custom_verification_mapper, custom_certificate_mapper
from vdx_helper.errors import error_from_response
from vdx_helper.mappers import get_paginated_mapper, file_mapper
from vdx_helper.vdx_helper import VDXHelper


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
        return VDXHelper(api_url=self.mock_endpoint, auth_url=self.keycloak_url,
                         client_secret=self.core_api_key, client_id=self.core_api_client_id)

    @classmethod
    def setUpClass(cls) -> None:
        if cls.mock_server is not None:
            cls.mock_server.start()
            cls.mock_server.wait_for(cls.mock_endpoint)

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.mock_server is not None:
            cls.mock_server.stop()

    @patch('vdx_helper.vdx_helper.VDXHelper._token', new_callable=PropertyMock)
    def test_get_files(self, _token) -> None:
        _token.return_value = "vizidox-authorization"
        vdx_helper = self.get_vdx_helper()
        files = vdx_helper.get_files()
        assert files is not None

    def test_upload_file(self):
        # TODO Missing file request validation
        #  This test only validates mocked responses for upload_file endpoint for now due to an error in the request
        #  {
        #     "statusCode": 400,
        #     "code": "FST_ERR_CTP_INVALID_CONTENT_LENGTH",
        #     "error": "Bad Request",
        #     "message": "FST_ERR_CTP_INVALID_CONTENT_LENGTH: Request body size did not match Content-Length"
        #  }
        #  It seems it is a common issue: https://github.com/stoplightio/prism/issues/432 still yet to be fixed.
        #  Jira issue: VDX-857

        headers = {
            "Authorization": "Bearer " + "token",
            "Accept": "application/json"
        }
        response = requests.post(
            f"{self.mock_endpoint}/files",
            headers=headers
        )

        status = HTTPStatus(response.status_code)

        if status not in [HTTPStatus.OK, HTTPStatus.CREATED]:
            raise error_from_response(status, response)

        file_summary = file_mapper(response.json()["result"])

        assert file_summary is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._token', new_callable=PropertyMock)
    def test_get_credentials(self, _token):
        _token.return_value = "vizidox-authorization"
        vdx_helper = self.get_vdx_helper()

        credentials = vdx_helper.get_credentials(mapper=get_paginated_mapper(custom_credential_mapper))
        assert credentials is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._token', new_callable=PropertyMock)
    def test_get_credential(self, _token):
        _token.return_value = "vizidox-authorization"
        vdx_helper = self.get_vdx_helper()
        cred_uid = UUID('189e4e5c-833d-430b-9baa-5230841d997f')
        credential = vdx_helper.get_credential(cred_uid, mapper=custom_credential_mapper)
        assert credential is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._token', new_callable=PropertyMock)
    def test_create_credential(self, _token):
        _token.return_value = "vizidox-authorization"
        vdx_helper = self.get_vdx_helper()

        title = 'title'
        metadata = {}
        tags = ["tagA", "tagB", "tagC"]
        file_hashes = ['123456789']
        cred_ids = [UUID('123e4567-e89b-12d3-a456-426655440000')]
        expiry_date = "2020-02-11T15:34:05.814607+00:00"

        credential = vdx_helper.create_credential(title=title, tags=tags, metadata=metadata, file_hashes=file_hashes,
                                                  cred_ids=cred_ids, expiry_date=expiry_date, mapper=custom_credential_mapper)
        assert credential is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._token', new_callable=PropertyMock)
    def test_issue_job(self, _token):
        _token.return_value = "vizidox-authorization"
        vdx_helper = self.get_vdx_helper()
        engine = 'dogecoin'

        job = vdx_helper.issue_job(engine=engine, mapper=custom_job_mapper)
        assert job is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._token', new_callable=PropertyMock)
    def test_get_job(self, _token):
        _token.return_value = "vizidox-authorization"
        vdx_helper = self.get_vdx_helper()
        job_uid = UUID('939a9ccb-ddf9-424c-94eb-91898455a968')
        job = vdx_helper.get_job(job_uid, mapper=custom_job_mapper)
        assert job is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._token', new_callable=PropertyMock)
    def test_get_jobs(self, _token):
        _token.return_value = "vizidox-authorization"
        vdx_helper = self.get_vdx_helper()
        jobs = vdx_helper.get_jobs(mapper=get_paginated_mapper(custom_job_mapper))
        assert jobs is not None

    def test_verify_by_file(self):
        # TODO Missing file request validation
        #  This test only validates mocked responses for upload_file endpoint for now due to an error in the request
        #  {
        #     "statusCode": 400,
        #     "code": "FST_ERR_CTP_INVALID_CONTENT_LENGTH",
        #     "error": "Bad Request",
        #     "message": "FST_ERR_CTP_INVALID_CONTENT_LENGTH: Request body size did not match Content-Length"
        #  }
        #  It seems it is a common issue: https://github.com/stoplightio/prism/issues/432 still yet to be fixed.
        #  Jira issue: https://vizidox.atlassian.net/browse/VDX-857
        headers = {
            "Authorization": "Bearer " + "token",
            "Accept": "application/json"
        }
        response = requests.post(
            f"{self.mock_endpoint}/verify/upload/file",
            headers=headers
        )

        status = HTTPStatus(response.status_code)
        if status is not HTTPStatus.OK:
            raise error_from_response(status, response)

        verification_response = get_paginated_mapper(custom_verification_mapper)(response.json()["result"])

        assert verification_response is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._token', new_callable=PropertyMock)
    def test_verify_by_credential_uid(self, _token):
        vdx_helper = self.get_vdx_helper()
        _token.return_value = "vizidox-authorization"

        cred_id = UUID('123e4567-e89b-12d3-a456-426655440000')
        verification_response = vdx_helper.verify_by_credential_uid(cred_uid=cred_id,
                                                                    mapper=get_paginated_mapper(custom_verification_mapper))
        assert verification_response is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._token', new_callable=PropertyMock)
    def test_verify_by_certificate_uid(self, _token):
        vdx_helper = self.get_vdx_helper()
        _token.return_value = "vizidox-authorization"
        cert_uid = UUID('123e4567-e89b-12d3-a456-426655440000')
        verification_response = vdx_helper.verify_by_uid(cert_uid=cert_uid, mapper=custom_verification_mapper)
        assert verification_response is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._token', new_callable=PropertyMock)
    def test_get_certificates(self, _token):
        _token.return_value = "vizidox-authorization"
        vdx_helper = self.get_vdx_helper()

        certificates = vdx_helper.get_certificates(mapper=get_paginated_mapper(custom_certificate_mapper))
        assert certificates is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._token', new_callable=PropertyMock)
    def test_revoke_certificate(self, _token):
        vdx_helper = self.get_vdx_helper()
        _token.return_value = "vizidox-authorization"
        cert_uid = UUID("939a9ccb-ddf9-424c-94eb-91898455a968")
        vdx_helper.revoke_certificate(cert_uid=cert_uid)

    @patch('vdx_helper.vdx_helper.VDXHelper._token', new_callable=PropertyMock)
    def test_download_certificate(self, _token):
        # WARNING: Prism does not currently support mocked file types for application/octet-stream
        # so the swagger.json file was changed to reproduce that. It produces "application/json" instead.
        # https://github.com/stoplightio/prism/issues/432
        # Jira issue: VDX-857

        vdx_helper = self.get_vdx_helper()
        _token.return_value = "vizidox-authorization"
        cert_uid = UUID("939a9ccb-ddf9-424c-94eb-91898455a968")

        certificate = vdx_helper.download_certificate(cert_uid=cert_uid)

        assert certificate is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._token', new_callable=PropertyMock)
    def test_get_job_certificates(self, _token):
        vdx_helper = self.get_vdx_helper()
        _token.return_value = "vizidox-authorization"
        job_uid = UUID("939a9ccb-ddf9-424c-94eb-91898455a968")
        certificates = vdx_helper.get_job_certificates(job_uid=job_uid, pagination=None,
                                                       mapper=get_paginated_mapper(custom_certificate_mapper))
        assert certificates is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._token', new_callable=PropertyMock)
    def test_get_job_credentials(self, _token):
        _token.return_value = "vizidox-authorization"
        vdx_helper = self.get_vdx_helper()
        job_uid = UUID("939a9ccb-ddf9-424c-94eb-91898455a968")

        credentials = vdx_helper.get_job_credentials(job_uid=job_uid, mapper=get_paginated_mapper(
            custom_credential_mapper))
        assert credentials is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._token', new_callable=PropertyMock)
    def test_schedule_credentials(self, _token):
        vdx_helper = self.get_vdx_helper()
        _token.return_value = "vizidox-authorization"
        engine = 'dogecoin'
        credentials = [UUID("939a9ccb-ddf9-424c-94eb-91898455a968"), UUID("39c7ddcd-f480-48e5-8056-fabf84e7f859")]

        job = vdx_helper.schedule_credentials(engine=engine, credentials=credentials, mapper=custom_job_mapper)
        assert job is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._token', new_callable=PropertyMock)
    def test_get_file(self, _token):
        vdx_helper = self.get_vdx_helper()
        _token.return_value = "vizidox-authorization"
        file_hash = "123456789"
        file = vdx_helper.get_file(file_hash=file_hash)
        assert file is not None

    @patch('vdx_helper.vdx_helper.VDXHelper._token', new_callable=PropertyMock)
    def test_update_job_tags(self, _token):
        vdx_helper = self.get_vdx_helper()
        _token.return_value = "vizidox-authorization"
        updated_job_tags = [{"tag": "tag"}]
        vdx_helper.update_job_tags(updated_job_tags=updated_job_tags)

    @patch('vdx_helper.vdx_helper.VDXHelper._token', new_callable=PropertyMock)
    def test_replace_job_tags(self, _token):
        vdx_helper = self.get_vdx_helper()
        _token.return_value = "vizidox-authorization"
        replace_job_tags = [{"tag": "tag"}]
        vdx_helper.replace_job_tags(replace_job_tags=replace_job_tags)

    @patch('vdx_helper.vdx_helper.VDXHelper._token', new_callable=PropertyMock)
    def test_update_credential_tags(self, _token):
        vdx_helper = self.get_vdx_helper()
        _token.return_value = "vizidox-authorization"
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

    @patch('vdx_helper.vdx_helper.VDXHelper._token', new_callable=PropertyMock)
    def test_replace_credential_tags(self, _token):
        vdx_helper = self.get_vdx_helper()
        _token.return_value = "vizidox-authorization"
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

    @patch('vdx_helper.vdx_helper.VDXHelper._token', new_callable=PropertyMock)
    def test_delete_credential_tag(self, _token):
        vdx_helper = self.get_vdx_helper()
        _token.return_value = "vizidox-authorization"
        credential_tag = "tagA"
        cred_uid = UUID("d39fca4b-5f7a-4e7d-8c1e-665988de808e")

        vdx_helper.delete_credential_tag(cred_uid=cred_uid, tag=credential_tag)
