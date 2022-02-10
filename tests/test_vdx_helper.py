import copy
import unittest
from datetime import datetime
from http import HTTPStatus
from typing import Callable
from unittest.mock import patch, MagicMock, PropertyMock
from uuid import UUID

from tests.json_responses import file_json, mapped_file, credential_json, \
    mapped_credential, paginated_credential, mapped_paginated_credential, job_json, mapped_job, paginated_job, \
    mapped_paginated_job, verification_response_json, mapped_verification, mapped_paginated_certificate, \
    paginated_certificate, paginated_file, mapped_paginated_file
from vdx_helper.errors import VDXError
from vdx_helper.mappers import json_mapper
from vdx_helper.vdx_helper import VDXHelper


class VdxHelperTest(unittest.TestCase):
    def setUp(self):
        self.api_url = "vizidox.com"
        self.auth_url = "https://vizidox-keycloak.com"
        self.client_secret = 'core_api_key'
        self.client_id = 'core_api_client_id'
        self.default_current_time = 300
        self.default_json_value = {'name': 'vizidox', 'value': 123}

    def get_vdx_helper(self):
        return VDXHelper(
            api_url=self.api_url,
            auth_url=self.auth_url,
            client_secret=self.client_secret,
            client_id=self.client_id,
        )

    def test_initialization(self):
        vdx_helper = self.get_vdx_helper()
        self.assertEqual(self.api_url, vdx_helper.api_url)
        self.assertEqual(self.auth_url, vdx_helper.auth_url)

    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.time')
    def test_fetch_token(self, time, requests):
        vdx_helper = self.get_vdx_helper()
        time.time.return_value = self.default_current_time
        response = MagicMock()
        requests.post.return_value = response
        # OK status
        response.status_code = HTTPStatus.OK
        response.json.return_value = {'access_token': 'vizidox-access-token',
                                      'expires_in': 50}

        access_token, token_expiration_date = vdx_helper._fetch_token()
        self.assertEqual(token_expiration_date, self.default_current_time + 50)
        self.assertEqual('vizidox-access-token', access_token)
        # not OK status
        response.status_code = HTTPStatus.CONFLICT
        response.json.return_value = {}

        self.assertRaises(VDXError, vdx_helper._fetch_token)

    @patch('vdx_helper.vdx_helper.time')
    @patch('vdx_helper.vdx_helper.VDXHelper._fetch_token')
    def test_token(self, _fetch_token, time):
        vdx_helper = self.get_vdx_helper()
        vdx_helper.auth_token = 'abc'
        time.time.return_value = self.default_current_time
        auth_token = "vizidox-auth-token"
        _fetch_token.return_value = (auth_token, self.default_current_time + 100)

        # not expired
        vdx_helper.token_expiration_date = self.default_current_time + 100
        new_auth_token = vdx_helper._token
        self.assertEqual(new_auth_token, 'abc')

        # expired
        vdx_helper.token_expiration_date = self.default_current_time - 100
        new_auth_token = vdx_helper._token
        self.assertEqual(new_auth_token, auth_token)

        # API Authentication failed
        vdx_helper.token_expiration_date = self.default_current_time - 100
        error_auth_token = None
        _fetch_token.reset_mock()
        _fetch_token.side_effect = VDXError(HTTPStatus.SERVICE_UNAVAILABLE, "API Authentication failed")
        try:
            error_auth_token = vdx_helper._token
        except VDXError:
            self.assertIsNone(error_auth_token)

    @patch('vdx_helper.vdx_helper.VDXHelper._token', new_callable=PropertyMock)
    def test_header(self, _token):
        _token.return_value = "vizidox-authorization"
        vdx_helper = self.get_vdx_helper()
        expected_header = {
            "Authorization": "Bearer " + "vizidox-authorization",
            "Accept": "application/json"
        }
        header = vdx_helper.header
        self.assertDictEqual(expected_header, header)

    def new_mapper(self) -> Callable:
        def test_mapper(json_: dict) -> dict:
            new_json = copy.deepcopy(json_)
            new_json['testing_key'] = 'testing_value'
            return new_json

        return test_mapper

    @patch('vdx_helper.vdx_helper.VDXHelper.header')
    @patch('vdx_helper.vdx_helper.requests')
    def test_upload_file(self, requests, header):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        # file
        stream = MagicMock()

        # response
        response.json.return_value = file_json
        requests.post.return_value = response

        # OK status
        response.status_code = HTTPStatus.OK
        file_summary = vdx_helper.upload_file(stream)
        self.assertEqual(file_summary, mapped_file)
        file_info = requests.post.call_args[1]['files']['file']
        self.assertEqual(file_info, stream)

        # not OK status
        file_summary = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            file_summary = vdx_helper.upload_file(stream)
        except VDXError:
            self.assertIsNone(file_summary)
            file_info = requests.post.call_args[1]['files']['file']
            self.assertEqual(file_info, stream)

        # json mapper
        response.status_code = HTTPStatus.OK
        json_result = vdx_helper.upload_file(stream, mapper=json_mapper)
        self.assertDictEqual(json_result, file_json)
        file_info = requests.post.call_args[1]['files']['file']
        self.assertEqual(file_info, stream)

    @patch('vdx_helper.vdx_helper.VDXHelper.header')
    @patch('vdx_helper.vdx_helper.requests')
    def test_get_credentials(self, requests, header):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.get.return_value = response
        response.json.return_value = paginated_credential

        # OK case
        response.status_code = HTTPStatus.OK
        credentials = vdx_helper.get_credentials()
        self.assertEqual(credentials, mapped_paginated_credential)
        self.assertEqual(f"{self.api_url}/credentials", requests.get.call_args[0][0])

        # not OK case
        credentials = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            credentials = vdx_helper.get_credentials()
        except VDXError:
            self.assertIsNone(credentials)
            self.assertEqual(f"{self.api_url}/credentials", requests.get.call_args[0][0])

        # with json mapper
        response.status_code = HTTPStatus.OK
        credentials = vdx_helper.get_credentials(mapper=json_mapper)
        self.assertEqual(f"{self.api_url}/credentials", requests.get.call_args[0][0])
        self.assertDictEqual(credentials, paginated_credential)

    @patch('vdx_helper.vdx_helper.VDXHelper.header')
    @patch('vdx_helper.vdx_helper.requests')
    def test_get_credential(self, requests, header):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.get.return_value = response
        response.json.return_value = credential_json
        cred_uid = UUID('189e4e5c-833d-430b-9baa-5230841d997f')

        # OK case
        response.status_code = HTTPStatus.OK
        credential = vdx_helper.get_credential(cred_uid)
        self.assertEqual(credential, mapped_credential)
        self.assertEqual(f"{self.api_url}/credentials/{cred_uid}", requests.get.call_args[0][0])

        # not OK case
        credential = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            credential = vdx_helper.get_credential(cred_uid)
        except VDXError:
            self.assertIsNone(credential)
            self.assertEqual(f"{self.api_url}/credentials/{cred_uid}", requests.get.call_args[0][0])

        # with json mapper
        response.status_code = HTTPStatus.OK
        credential = vdx_helper.get_credential(cred_uid=cred_uid, mapper=json_mapper)
        self.assertEqual(f"{self.api_url}/credentials/{cred_uid}", requests.get.call_args[0][0])
        self.assertDictEqual(credential, credential_json)

    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper.header')
    def test_create_credential(self, header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.post.return_value = response
        response.json.return_value = credential_json

        title = 'title'
        metadata = {}
        tags = ["example"]
        file_hashes = ['123456789']
        cred_ids = [UUID('939a9ccb-ddf9-424c-94eb-91898455a968')]
        expiry_date = "2021-01-01T15:34:05.814607+00:00"

        # OK case
        response.status_code = HTTPStatus.OK
        credential = vdx_helper.create_credential(title=title, tags=tags, metadata=metadata, file_hashes=file_hashes,
                                                  cred_ids=cred_ids, expiry_date=expiry_date)
        self.assertEqual(credential, mapped_credential)
        self.assertEqual(f"{self.api_url}/credentials", requests.post.call_args[0][0])

        # not OK case
        credential = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            credential = vdx_helper.create_credential(title=title, tags=tags, metadata=metadata, file_hashes=file_hashes,
                                                      cred_ids=cred_ids, expiry_date=expiry_date)
        except VDXError:
            self.assertIsNone(credential)
            self.assertEqual(f"{self.api_url}/credentials", requests.post.call_args[0][0])

        # with json mapper
        response.status_code = HTTPStatus.OK
        credential = vdx_helper.create_credential(title=title, tags=tags, metadata=metadata, file_hashes=file_hashes,
                                                  cred_ids=cred_ids, expiry_date=expiry_date, mapper=json_mapper)
        self.assertEqual(f"{self.api_url}/credentials", requests.post.call_args[0][0])
        self.assertDictEqual(credential, credential_json)

    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper.header')
    def test_issue_job(self, header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.post.return_value = response
        response.json.return_value = job_json
        engine = 'dogecoin'
        # Success status
        response.status_code = HTTPStatus.CREATED
        job = vdx_helper.issue_job(engine=engine)
        self.assertEqual(mapped_job, job)
        self.assertEqual(f"{self.api_url}/jobs/immediate", requests.post.call_args[0][0])

        # not OK status
        job = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            job = vdx_helper.issue_job(engine=engine)
        except VDXError:
            self.assertIsNone(job)
            self.assertEqual(f"{self.api_url}/jobs/immediate", requests.post.call_args[0][0])

        # with custom mapper
        response.status_code = HTTPStatus.CREATED
        job = vdx_helper.issue_job(engine=engine, mapper=json_mapper)
        self.assertEqual(f"{self.api_url}/jobs/immediate", requests.post.call_args[0][0])
        self.assertDictEqual(job, job_json)

    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper.header')
    def test_get_job(self, header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.get.return_value = response
        response.json.return_value = job_json
        job_uid = UUID(job_json['uid'])
        # OK status
        response.status_code = HTTPStatus.OK
        job = vdx_helper.get_job(job_uid)
        self.assertEqual(mapped_job, job)
        self.assertEqual(f"{self.api_url}/jobs/{job_uid}", requests.get.call_args[0][0])

        # not OK status
        job = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            job = vdx_helper.get_job(job_uid)
        except VDXError:
            self.assertIsNone(job)
            self.assertEqual(f"{self.api_url}/jobs/{job_uid}", requests.get.call_args[0][0])

        # with custom mapper
        response.status_code = HTTPStatus.OK
        job = vdx_helper.get_job(job_uid=job_uid, mapper=json_mapper)
        self.assertEqual(f"{self.api_url}/jobs/{job_uid}", requests.get.call_args[0][0])
        self.assertDictEqual(job, job_json)

    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper.header')
    def test_get_jobs(self, header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.get.return_value = response
        response.json.return_value = paginated_job
        # OK status
        response.status_code = HTTPStatus.OK
        job = vdx_helper.get_jobs()
        self.assertEqual(mapped_paginated_job, job)
        self.assertEqual(f"{self.api_url}/jobs", requests.get.call_args[0][0])

        # not OK status
        job = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            job = vdx_helper.get_jobs()
        except VDXError:
            self.assertIsNone(job)
            self.assertEqual(f"{self.api_url}/jobs", requests.get.call_args[0][0])

        # with custom mapper
        response.status_code = HTTPStatus.OK
        job = vdx_helper.get_jobs(mapper=json_mapper)
        self.assertEqual(f"{self.api_url}/jobs", requests.get.call_args[0][0])
        self.assertDictEqual(job, paginated_job)

    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper.header')
    def test_verify_by_uid(self, header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.get.return_value = response
        response.json.return_value = verification_response_json

        cert_uid = UUID('189e4e5c-833d-430b-9baa-5230841d997f')

        # OK status
        response.status_code = HTTPStatus.OK
        verification_response = vdx_helper.verify_by_uid(cert_uid)
        self.assertEqual(mapped_verification, verification_response)
        self.assertEqual(f"{self.api_url}/verify/{cert_uid}", requests.get.call_args[0][0])

        # not OK status
        verification_response = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            verification_response = vdx_helper.verify_by_uid(cert_uid)
        except VDXError:
            self.assertIsNone(verification_response)
            self.assertEqual(f"{self.api_url}/verify/{cert_uid}", requests.get.call_args[0][0])

        # with custom mapper
        response.status_code = HTTPStatus.OK
        verification_response = vdx_helper.verify_by_uid(cert_uid=cert_uid, mapper=json_mapper)
        self.assertEqual(f"{self.api_url}/verify/{cert_uid}", requests.get.call_args[0][0])
        self.assertDictEqual(verification_response, verification_response_json)

    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper.header')
    def test_verify_by_certificate(self, header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.post.return_value = response
        response.json.return_value = verification_response_json

        # file
        file_stream = MagicMock()
        filename = "file_name"
        file_content_type = "content_type"
        # OK status
        response.status_code = HTTPStatus.OK
        verification_response = vdx_helper.verify_by_certificate(filename=filename, file_stream=file_stream,
                                                                 file_content_type=file_content_type)
        self.assertEqual(mapped_verification, verification_response)
        self.assertEqual(f"{self.api_url}/verify/upload/certificate", requests.post.call_args[0][0])

        # not OK status
        verification_response = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            verification_response = vdx_helper.verify_by_certificate(filename=filename, file_stream=file_stream,
                                                                     file_content_type=file_content_type)
        except VDXError:
            self.assertIsNone(verification_response)
            self.assertEqual(f"{self.api_url}/verify/upload/certificate", requests.post.call_args[0][0])

        # with custom mapper
        response.status_code = HTTPStatus.OK
        verification_response = vdx_helper.verify_by_certificate(filename=filename, file_stream=file_stream,
                                                                 file_content_type=file_content_type,
                                                                 mapper=json_mapper)
        self.assertEqual(f"{self.api_url}/verify/upload/certificate", requests.post.call_args[0][0])
        self.assertDictEqual(verification_response, verification_response_json)

    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper.header')
    def test_verify_by_file(self, header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.post.return_value = response
        response.json.return_value = verification_response_json

        # file
        file_stream = MagicMock()
        filename = "file_name"
        file_content_type = "content_type"
        # OK status
        response.status_code = HTTPStatus.OK
        verification_response = vdx_helper.verify_by_file(filename=filename, file_stream=file_stream,
                                                          file_content_type=file_content_type)
        self.assertEqual(mapped_verification, verification_response)
        self.assertEqual(f"{self.api_url}/verify/upload/file", requests.post.call_args[0][0])

        # not OK status
        verification_response = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            verification_response = vdx_helper.verify_by_file(filename=filename, file_stream=file_stream,
                                                              file_content_type=file_content_type)
        except VDXError:
            self.assertIsNone(verification_response)
            self.assertEqual(f"{self.api_url}/verify/upload/file", requests.post.call_args[0][0])

        # with custom mapper
        response.status_code = HTTPStatus.OK
        verification_response = vdx_helper.verify_by_file(filename=filename, file_stream=file_stream,
                                                          file_content_type=file_content_type, mapper=json_mapper)
        self.assertEqual(f"{self.api_url}/verify/upload/file", requests.post.call_args[0][0])
        self.assertDictEqual(verification_response, verification_response_json)

    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper.header')
    def test_verify_by_credential_uid(self, header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.get.return_value = response
        response.json.return_value = verification_response_json

        cred_uid = UUID('189e4e5c-833d-430b-9baa-5230841d997f')

        # OK status
        response.status_code = HTTPStatus.OK
        verification_response = vdx_helper.verify_by_credential_uid(cred_uid=cred_uid)
        self.assertEqual(mapped_verification, verification_response)
        self.assertEqual(f"{self.api_url}/verify/credential/{cred_uid}", requests.get.call_args[0][0])

        # not OK status
        verification_response = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            verification_response = vdx_helper.verify_by_credential_uid(cred_uid=cred_uid)
        except VDXError:
            self.assertIsNone(verification_response)
            self.assertEqual(f"{self.api_url}/verify/credential/{cred_uid}", requests.get.call_args[0][0])

        # with custom mapper
        response.status_code = HTTPStatus.OK
        verification_response = vdx_helper.verify_by_credential_uid(cred_uid=cred_uid, mapper=json_mapper)
        self.assertEqual(f"{self.api_url}/verify/credential/{cred_uid}", requests.get.call_args[0][0])
        self.assertDictEqual(verification_response, verification_response_json)

    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper.header')
    def test_get_certificates(self, header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.get.return_value = response
        response.json.return_value = paginated_certificate

        # OK status
        response.status_code = HTTPStatus.OK
        certificates = vdx_helper.get_certificates()
        self.assertEqual(mapped_paginated_certificate, certificates)
        self.assertEqual(f"{self.api_url}/certificates", requests.get.call_args[0][0])

        # not OK status
        certificates = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            certificates = vdx_helper.get_certificates()
        except VDXError:
            self.assertIsNone(certificates)
            self.assertEqual(f"{self.api_url}/certificates", requests.get.call_args[0][0])

        # with custom mapper
        response.status_code = HTTPStatus.OK
        certificates = vdx_helper.get_certificates(mapper=json_mapper)
        self.assertEqual(f"{self.api_url}/certificates", requests.get.call_args[0][0])
        self.assertDictEqual(paginated_certificate, certificates)

    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper.header')
    def test_revoke_certificate(self, header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.post.return_value = response
        cert_uid = UUID("939a9ccb-ddf9-424c-94eb-91898455a968")
        example_revoked_date = "2020-02-11T15:34:05.813217+00:00"

        # OK case
        response.status_code = HTTPStatus.OK
        response.json.return_value = example_revoked_date
        revoked_date = vdx_helper.revoke_certificate(cert_uid=cert_uid)
        self.assertEqual(f"{self.api_url}/certificates/{cert_uid}/revoke", requests.post.call_args[0][0])
        assert revoked_date == datetime.fromisoformat(example_revoked_date)

        # not OK case
        response.status_code = HTTPStatus.CONFLICT
        try:
            vdx_helper.revoke_certificate(cert_uid=cert_uid)
        except VDXError:
            self.assertEqual(f"{self.api_url}/certificates/{cert_uid}/revoke", requests.post.call_args[0][0])

    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.io')
    @patch('vdx_helper.vdx_helper.VDXHelper.header')
    def test_download_certificate(self, header, io, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.get.return_value = response
        io.BytesIO.return_value = "certificate"
        cert_uid = UUID("939a9ccb-ddf9-424c-94eb-91898455a968")

        # OK case
        response.status_code = HTTPStatus.OK
        certificate = vdx_helper.download_certificate(cert_uid=cert_uid)
        self.assertEqual("certificate", certificate)
        self.assertEqual(f"{self.api_url}/certificates/{cert_uid}/download", requests.get.call_args[0][0])

        # not OK case
        certificate = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            certificate = vdx_helper.download_certificate(cert_uid=cert_uid)
        except VDXError:
            self.assertIsNone(certificate)
            self.assertEqual(f"{self.api_url}/certificates/{cert_uid}/download", requests.get.call_args[0][0])

    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper.header')
    def test_get_job_certificates(self, header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.get.return_value = response
        response.json.return_value = paginated_certificate
        job_uid = UUID("939a9ccb-ddf9-424c-94eb-91898455a968")

        # OK status
        response.status_code = HTTPStatus.OK
        certificates = vdx_helper.get_job_certificates(job_uid=job_uid, pagination=None)
        self.assertEqual(mapped_paginated_certificate, certificates)
        self.assertEqual(f"{self.api_url}/jobs/{job_uid}/certificates", requests.get.call_args[0][0])

        # not OK status
        certificates = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            certificates = vdx_helper.get_job_certificates(job_uid=job_uid)
        except VDXError:
            self.assertIsNone(certificates)
            self.assertEqual(f"{self.api_url}/jobs/{job_uid}/certificates", requests.get.call_args[0][0])

        # with custom mapper
        response.status_code = HTTPStatus.OK
        certificates = vdx_helper.get_job_certificates(job_uid=job_uid, mapper=json_mapper)
        self.assertEqual(f"{self.api_url}/jobs/{job_uid}/certificates", requests.get.call_args[0][0])
        self.assertDictEqual(certificates, paginated_certificate)

    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper.header')
    def test_get_job_credentials(self, header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.get.return_value = response
        response.json.return_value = paginated_credential
        job_uid = UUID("939a9ccb-ddf9-424c-94eb-91898455a968")

        # OK status
        response.status_code = HTTPStatus.OK
        credentials = vdx_helper.get_job_credentials(job_uid=job_uid)
        self.assertEqual(credentials, mapped_paginated_credential)
        self.assertEqual(f"{self.api_url}/jobs/{job_uid}/credentials", requests.get.call_args[0][0])

        # not OK status
        credentials = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            credentials = vdx_helper.get_job_credentials(job_uid=job_uid)
        except VDXError:
            self.assertIsNone(credentials)
            self.assertEqual(f"{self.api_url}/jobs/{job_uid}/credentials", requests.get.call_args[0][0])

        # with custom mapper
        response.status_code = HTTPStatus.OK
        credentials = vdx_helper.get_job_credentials(job_uid=job_uid, mapper=json_mapper)
        self.assertEqual(f"{self.api_url}/jobs/{job_uid}/credentials", requests.get.call_args[0][0])
        self.assertDictEqual(credentials, paginated_credential)

    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper.header')
    def test_schedule_credentials(self, header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.post.return_value = response
        response.json.return_value = job_json
        engine = 'dogecoin'
        credentials = [UUID("939a9ccb-ddf9-424c-94eb-91898455a968"), UUID("39c7ddcd-f480-48e5-8056-fabf84e7f859")]
        # Success status
        response.status_code = HTTPStatus.CREATED
        job = vdx_helper.schedule_credentials(engine=engine, credentials=credentials)
        self.assertEqual(mapped_job, job)
        self.assertEqual(f"{self.api_url}/credentials/schedule", requests.post.call_args[0][0])

        # not OK status
        job = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            job = vdx_helper.schedule_credentials(engine=engine, credentials=credentials)
        except VDXError:
            self.assertIsNone(job)
            self.assertEqual(f"{self.api_url}/credentials/schedule", requests.post.call_args[0][0])

        # with custom mapper
        response.status_code = HTTPStatus.CREATED
        job = vdx_helper.schedule_credentials(engine=engine, credentials=credentials, mapper=json_mapper)
        self.assertEqual(f"{self.api_url}/credentials/schedule", requests.post.call_args[0][0])
        self.assertDictEqual(job, job_json)

    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper.header')
    def test_get_files(self, header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.get.return_value = response
        response.json.return_value = paginated_file

        # OK status
        response.status_code = HTTPStatus.OK
        files = vdx_helper.get_files()
        self.assertEqual(files, mapped_paginated_file)
        self.assertEqual(f"{self.api_url}/files", requests.get.call_args[0][0])

        # not OK status
        files = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            files = vdx_helper.get_files()
        except VDXError:
            self.assertIsNone(files)
            self.assertEqual(f"{self.api_url}/files", requests.get.call_args[0][0])

        # with custom mapper
        response.status_code = HTTPStatus.OK
        files = vdx_helper.get_files(mapper=json_mapper)
        self.assertEqual(f"{self.api_url}/files", requests.get.call_args[0][0])
        self.assertDictEqual(files, paginated_file)

    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper.header')
    def test_get_file(self, header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.get.return_value = response
        response.json.return_value = file_json
        file_hash = "123456789"
        # OK status
        response.status_code = HTTPStatus.OK
        file = vdx_helper.get_file(file_hash=file_hash)
        self.assertEqual(mapped_file, file)
        self.assertEqual(f"{self.api_url}/files/{file_hash}", requests.get.call_args[0][0])

        # not OK status
        file = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            file = vdx_helper.get_file(file_hash=file_hash)
        except VDXError:
            self.assertIsNone(file)
            self.assertEqual(f"{self.api_url}/files/{file_hash}", requests.get.call_args[0][0])

        # with custom mapper
        response.status_code = HTTPStatus.OK
        file = vdx_helper.get_file(file_hash=file_hash, mapper=json_mapper)
        self.assertEqual(f"{self.api_url}/files/{file_hash}", requests.get.call_args[0][0])
        self.assertDictEqual(file, file_json)

    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper.header')
    def test_update_job_tags(self, header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.patch.return_value = response
        updated_job_tags = [{"tag": "tag"}]

        # OK case
        response.status_code = HTTPStatus.OK
        vdx_helper.update_job_tags(updated_job_tags=updated_job_tags)
        self.assertEqual(f"{self.api_url}/jobs", requests.patch.call_args[0][0])

        # not OK case
        response.status_code = HTTPStatus.CONFLICT
        try:
            vdx_helper.update_job_tags(updated_job_tags=updated_job_tags)
        except VDXError:
            self.assertEqual(f"{self.api_url}/jobs", requests.patch.call_args[0][0])

    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper.header')
    def test_replace_job_tags(self, header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.put.return_value = response
        replace_job_tags = [{"tag": "tag"}]

        # OK case
        response.status_code = HTTPStatus.OK
        vdx_helper.replace_job_tags(replace_job_tags=replace_job_tags)
        self.assertEqual(f"{self.api_url}/jobs", requests.put.call_args[0][0])

        # not OK case
        response.status_code = HTTPStatus.CONFLICT
        try:
            vdx_helper.replace_job_tags(replace_job_tags=replace_job_tags)
        except VDXError:
            self.assertEqual(f"{self.api_url}/jobs", requests.put.call_args[0][0])

    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper.header')
    def test_update_credential_tags(self, header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.patch.return_value = response
        updated_credential_tags = [
            {
                "credential_uid": UUID("123e4567-e89b-12d3-a456-426655440000"),
                "tags": [
                    "tagA",
                    "tagB",
                    "tagC"
                ]
            }
        ]

        # OK case
        response.status_code = HTTPStatus.OK
        vdx_helper.update_credential_tags(updated_credential_tags=updated_credential_tags)
        self.assertEqual(f"{self.api_url}/credentials", requests.patch.call_args[0][0])

        # not OK case
        response.status_code = HTTPStatus.CONFLICT
        try:
            vdx_helper.update_credential_tags(updated_credential_tags=updated_credential_tags)
        except VDXError:
            self.assertEqual(f"{self.api_url}/credentials", requests.patch.call_args[0][0])

    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper.header')
    def test_replace_credential_tags(self, header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.put.return_value = response
        replace_credential_tags = [
            {
                "credential_uid": UUID("123e4567-e89b-12d3-a456-426655440000"),
                "tags": [
                    "tagA",
                    "tagB",
                    "tagC"
                ]
            }
        ]

        # OK case
        response.status_code = HTTPStatus.OK
        vdx_helper.replace_credential_tags(replace_credential_tags=replace_credential_tags)
        self.assertEqual(f"{self.api_url}/credentials", requests.put.call_args[0][0])

        # not OK case
        response.status_code = HTTPStatus.CONFLICT
        try:
            vdx_helper.replace_credential_tags(replace_credential_tags=replace_credential_tags)
        except VDXError:
            self.assertEqual(f"{self.api_url}/credentials", requests.put.call_args[0][0])

    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper.header')
    def test_delete_credential_tag(self, header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.patch.return_value = response
        credential_tag = "tagA"
        cred_uid = UUID("d39fca4b-5f7a-4e7d-8c1e-665988de808e")

        # OK case
        response.status_code = HTTPStatus.OK
        vdx_helper.delete_credential_tag(cred_uid=cred_uid, tag=credential_tag)
        self.assertEqual(f"{self.api_url}/credentials/{cred_uid}/delete_tag", requests.patch.call_args[0][0])

        # not OK case
        response.status_code = HTTPStatus.CONFLICT
        try:
            vdx_helper.delete_credential_tag(cred_uid=cred_uid, tag=credential_tag)
        except VDXError:
            self.assertEqual(f"{self.api_url}/credentials/{cred_uid}/delete_tag", requests.patch.call_args[0][0])
