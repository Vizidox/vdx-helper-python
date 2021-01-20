import copy
import unittest
from http import HTTPStatus
from typing import Dict, Any, Callable
from unittest.mock import patch, MagicMock
from uuid import UUID

from tests.json_responses import file_json, mapped_file, mapped_engine_permissions, engine_json, credential_json, \
    mapped_credential, paginated_credential, mapped_paginated_credential, job_json, mapped_job, paginated_job, \
    mapped_paginated_job, verification_response_json, mapped_verification, mapped_paginated_certificate, \
    paginated_certificate, paginated_file, mapped_paginated_file, engine_cost_json, mapped_engine_cost
from vdx_helper.vdx_helper import VDXHelper, VDXError, get_json_mapper

Json = Dict[str, Any]


class VdxHelperTest(unittest.TestCase):
    def setUp(self):
        self.url = "vizidox.com"
        self.keycloak_url = "http://vizidox-keycloak.com"
        self.core_api_key = 'core_api_key'
        self.core_api_client_id = 'core_api_client_id'
        self.default_current_time = 300
        self.default_json_value = {'name': 'vizidox', 'value': 123}

    def get_vdx_helper(self):
        vdx_helper = VDXHelper(url=self.url, keycloak_url=self.keycloak_url,
                               core_api_key=self.core_api_key, core_api_client_id=self.core_api_client_id)
        return vdx_helper

    def test_initialization(self):
        vdx_helper = self.get_vdx_helper()
        self.assertEqual(self.url, vdx_helper.url)
        self.assertEqual(self.keycloak_url, vdx_helper.keycloak_url)

    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.time')
    def test_get_token(self, time, requests):
        vdx_helper = self.get_vdx_helper()
        time.time.return_value = self.default_current_time
        response = MagicMock()
        requests.post.return_value = response
        # OK status
        response.status_code = HTTPStatus.OK
        response.json.return_value = {'access_token': 'vizidox-access-token',
                                      'expires_in': 50}

        status, access_token, token_expiration_date = vdx_helper._get_token()
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(token_expiration_date, self.default_current_time + 50)
        self.assertEqual('vizidox-access-token', access_token)
        # not OK status
        response.status_code = HTTPStatus.CONFLICT
        response.json.return_value = {'access_token': 'vizidox-access-token',
                                      'expires_in': 50}

        status, access_token, token_expiration_date = vdx_helper._get_token()
        self.assertEqual(status, HTTPStatus.CONFLICT)
        self.assertIsNone(token_expiration_date)
        self.assertIsNone(access_token)

    @patch('vdx_helper.vdx_helper.time')
    @patch('vdx_helper.vdx_helper.VDXHelper._get_token')
    def test_get_token_string(self, _get_token, time):
        vdx_helper = self.get_vdx_helper()
        vdx_helper.auth_token = 'abc'
        time.time.return_value = self.default_current_time
        auth_token = "vizidox-auth-token"
        _get_token.return_value = (HTTPStatus.OK, auth_token, self.default_current_time + 100)

        # not expired
        vdx_helper.token_expiration_date = self.default_current_time + 100
        new_auth_token = vdx_helper._get_token_string()
        self.assertEqual(new_auth_token, 'abc')

        # expired
        vdx_helper.token_expiration_date = self.default_current_time - 100
        new_auth_token = vdx_helper._get_token_string()
        self.assertEqual(new_auth_token, auth_token)

        # API Authentication failed
        vdx_helper.token_expiration_date = self.default_current_time - 100
        _get_token.reset_mock()
        _get_token.return_value = (HTTPStatus.OK, None, None)
        self.assertRaises(VDXError, vdx_helper._get_token_string)

    @patch('vdx_helper.vdx_helper.VDXHelper._get_token_string')
    def test_header(self, _get_token_string):
        _get_token_string.return_value = "vizidox-authorization"
        vdx_helper = self.get_vdx_helper()
        expected_header = {
            "Authorization": "Bearer " + "vizidox-authorization",
            "Accept": "application/json"
        }
        header = vdx_helper.header
        self.assertDictEqual(expected_header, header)

    def new_mapper(self) -> Callable:
        def test_mapper(json_: Json) -> Json:
            new_json = copy.deepcopy(json_)
            new_json['testing_key'] = 'testing_value'
            return new_json

        return test_mapper

    @patch('vdx_helper.vdx_helper.VDXHelper.header')
    @patch('vdx_helper.vdx_helper.requests')
    def test_get_partner_permissions(self, requests, header):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        response.json.return_value = engine_json
        requests.get.return_value = response
        # OK status
        response.status_code = HTTPStatus.OK
        permissions = vdx_helper.get_partner_permissions()
        self.assertListEqual(permissions, mapped_engine_permissions)

        # not OK status
        permissions = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            permissions = vdx_helper.get_partner_permissions()
        except VDXError:
            self.assertIsNone(permissions)

        # json mapper
        response.status_code = HTTPStatus.OK
        permissions = vdx_helper.get_partner_permissions(mapper=get_json_mapper())
        self.assertListEqual(permissions, engine_json)

    @patch('vdx_helper.vdx_helper.VDXHelper.header')
    @patch('vdx_helper.vdx_helper.requests')
    def test_get_engine_cost(self, requests, header):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        response.json.return_value = engine_cost_json
        requests.get.return_value = response
        # OK status
        response.status_code = HTTPStatus.OK
        engine_cost = vdx_helper.get_engine_cost(engine_name='bitcoin', n=10)
        self.assertEqual(engine_cost, mapped_engine_cost)

        # not OK status
        engine_cost = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            engine_cost = vdx_helper.get_engine_cost(engine_name='bitcoin', n=10)
        except VDXError:
            self.assertIsNone(engine_cost)

        # json mapper
        response.status_code = HTTPStatus.OK
        engine_cost = vdx_helper.get_engine_cost(engine_name='bitcoin', n=10, mapper=get_json_mapper())
        self.assertEqual(engine_cost, engine_cost_json)

    @patch('vdx_helper.vdx_helper.VDXHelper.header')
    @patch('vdx_helper.vdx_helper.requests')
    def test_upload_file(self, requests, header):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        # file
        filename = "name"
        stream = MagicMock()
        content_type = "content_type"

        # response
        response.json.return_value = file_json
        requests.post.return_value = response

        # OK status
        response.status_code = HTTPStatus.OK
        file_summary = vdx_helper.upload_file(filename, stream, content_type)
        self.assertEqual(file_summary, mapped_file)
        file_info = requests.post.call_args[1]['files']['file']
        self.assertEqual(file_info[0], "name")
        self.assertEqual(file_info[2], "content_type")

        # not OK status
        file_summary = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            file_summary = vdx_helper.upload_file(filename, stream, content_type)
        except VDXError:
            self.assertIsNone(file_summary)
            file_info = requests.post.call_args[1]['files']['file']
            self.assertEqual(file_info[0], "name")
            self.assertEqual(file_info[2], "content_type")

        # json mapper
        response.status_code = HTTPStatus.OK
        json_result = vdx_helper.upload_file(filename, stream, content_type, mapper=get_json_mapper())
        self.assertDictEqual(json_result, file_json)
        file_info = requests.post.call_args[1]['files']['file']
        self.assertEqual(file_info[0], "name")
        self.assertEqual(file_info[2], "content_type")

    @patch('vdx_helper.vdx_helper.VDXHelper.header')
    @patch('vdx_helper.vdx_helper.requests')
    def test_update_file_attributes(self, requests, header):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        filename = 'new_name'
        core_id = "core_id"

        # response
        response.status_code = HTTPStatus.OK
        requests.put.return_value = response

        vdx_helper.update_file_attributes(core_id=core_id, filename=filename)
        self.assertEqual(f"{self.url}/files/{core_id}/attributes", requests.put.call_args[0][0])

        # invalid ID
        response.status_code = HTTPStatus.NOT_FOUND
        try:
            vdx_helper.update_file_attributes(core_id=core_id, filename=filename)
        except VDXError:
            self.assertEqual(f"{self.url}/files/{core_id}/attributes", requests.put.call_args[0][0])

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
        self.assertEqual(f"{self.url}/credentials", requests.get.call_args[0][0])

        # not OK case
        credentials = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            credentials = vdx_helper.get_credentials()
        except VDXError:
            self.assertIsNone(credentials)
            self.assertEqual(f"{self.url}/credentials", requests.get.call_args[0][0])

        # with json mapper
        response.status_code = HTTPStatus.OK
        credentials = vdx_helper.get_credentials(mapper=get_json_mapper())
        self.assertEqual(f"{self.url}/credentials", requests.get.call_args[0][0])
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
        self.assertEqual(f"{self.url}/credentials/{cred_uid}", requests.get.call_args[0][0])

        # not OK case
        credential = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            credential = vdx_helper.get_credential(cred_uid)
        except VDXError:
            self.assertIsNone(credential)
            self.assertEqual(f"{self.url}/credentials/{cred_uid}", requests.get.call_args[0][0])

        # with json mapper
        response.status_code = HTTPStatus.OK
        credential = vdx_helper.get_credential(cred_uid=cred_uid, mapper=get_json_mapper())
        self.assertEqual(f"{self.url}/credentials/{cred_uid}", requests.get.call_args[0][0])
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
        core_ids = ['partner_123456789']
        cred_ids = [UUID('939a9ccb-ddf9-424c-94eb-91898455a968')]
        expiry_date = "2021-01-01T15:34:05.814607+00:00"

        # OK case
        response.status_code = HTTPStatus.OK
        credential = vdx_helper.create_credential(title=title, tags=tags, metadata=metadata, core_ids=core_ids,
                                                  cred_ids=cred_ids, expiry_date=expiry_date)
        self.assertEqual(credential, mapped_credential)
        self.assertEqual(f"{self.url}/credentials", requests.post.call_args[0][0])

        # not OK case
        credential = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            credential = vdx_helper.create_credential(title=title, tags=tags, metadata=metadata, core_ids=core_ids,
                                                      cred_ids=cred_ids, expiry_date=expiry_date)
        except VDXError:
            self.assertIsNone(credential)
            self.assertEqual(f"{self.url}/credentials", requests.post.call_args[0][0])

        # with json mapper
        response.status_code = HTTPStatus.OK
        credential = vdx_helper.create_credential(title=title, tags=tags, metadata=metadata, core_ids=core_ids,
                                                  cred_ids=cred_ids, expiry_date=expiry_date, mapper=get_json_mapper())
        self.assertEqual(f"{self.url}/credentials", requests.post.call_args[0][0])
        self.assertDictEqual(credential, credential_json)

    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper.header')
    def test_issue_job(self, header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.post.return_value = response
        response.json.return_value = job_json
        engine = 'dogecoin'
        # OK status
        response.status_code = HTTPStatus.OK
        job = vdx_helper.issue_job(engine=engine)
        self.assertEqual(mapped_job, job)
        self.assertEqual(f"{self.url}/jobs/immediate", requests.post.call_args[0][0])

        # not OK status
        job = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            job = vdx_helper.issue_job(engine=engine)
        except VDXError:
            self.assertIsNone(job)
            self.assertEqual(f"{self.url}/jobs/immediate", requests.post.call_args[0][0])

        # with custom mapper
        response.status_code = HTTPStatus.OK
        job = vdx_helper.issue_job(engine=engine, mapper=get_json_mapper())
        self.assertEqual(f"{self.url}/jobs/immediate", requests.post.call_args[0][0])
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
        self.assertEqual(f"{self.url}/jobs/{job_uid}", requests.get.call_args[0][0])

        # not OK status
        job = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            job = vdx_helper.get_job(job_uid)
        except VDXError:
            self.assertIsNone(job)
            self.assertEqual(f"{self.url}/jobs/{job_uid}", requests.get.call_args[0][0])

        # with custom mapper
        response.status_code = HTTPStatus.OK
        job = vdx_helper.get_job(job_uid=job_uid, mapper=get_json_mapper())
        self.assertEqual(f"{self.url}/jobs/{job_uid}", requests.get.call_args[0][0])
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
        self.assertEqual(f"{self.url}/jobs", requests.get.call_args[0][0])

        # not OK status
        job = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            job = vdx_helper.get_jobs()
        except VDXError:
            self.assertIsNone(job)
            self.assertEqual(f"{self.url}/jobs", requests.get.call_args[0][0])

        # with custom mapper
        response.status_code = HTTPStatus.OK
        job = vdx_helper.get_jobs(mapper=get_json_mapper())
        self.assertEqual(f"{self.url}/jobs", requests.get.call_args[0][0])
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
        self.assertEqual(f"{self.url}/verify/{cert_uid}", requests.get.call_args[0][0])

        # not OK status
        verification_response = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            verification_response = vdx_helper.verify_by_uid(cert_uid)
        except VDXError:
            self.assertIsNone(verification_response)
            self.assertEqual(f"{self.url}/verify/{cert_uid}", requests.get.call_args[0][0])

        # with custom mapper
        response.status_code = HTTPStatus.OK
        verification_response = vdx_helper.verify_by_uid(cert_uid=cert_uid, mapper=get_json_mapper())
        self.assertEqual(f"{self.url}/verify/{cert_uid}", requests.get.call_args[0][0])
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
        self.assertEqual(f"{self.url}/verify/upload/certificate", requests.post.call_args[0][0])

        # not OK status
        verification_response = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            verification_response = vdx_helper.verify_by_certificate(filename=filename, file_stream=file_stream,
                                                                     file_content_type=file_content_type)
        except VDXError:
            self.assertIsNone(verification_response)
            self.assertEqual(f"{self.url}/verify/upload/certificate", requests.post.call_args[0][0])

        # with custom mapper
        response.status_code = HTTPStatus.OK
        verification_response = vdx_helper.verify_by_certificate(filename=filename, file_stream=file_stream,
                                                                 file_content_type=file_content_type,
                                                                 mapper=get_json_mapper())
        self.assertEqual(f"{self.url}/verify/upload/certificate", requests.post.call_args[0][0])
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
        self.assertEqual(f"{self.url}/verify/upload/file", requests.post.call_args[0][0])

        # not OK status
        verification_response = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            verification_response = vdx_helper.verify_by_file(filename=filename, file_stream=file_stream,
                                                              file_content_type=file_content_type)
        except VDXError:
            self.assertIsNone(verification_response)
            self.assertEqual(f"{self.url}/verify/upload/file", requests.post.call_args[0][0])

        # with custom mapper
        response.status_code = HTTPStatus.OK
        verification_response = vdx_helper.verify_by_file(filename=filename, file_stream=file_stream,
                                                          file_content_type=file_content_type, mapper=get_json_mapper())
        self.assertEqual(f"{self.url}/verify/upload/file", requests.post.call_args[0][0])
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
        self.assertEqual(f"{self.url}/verify/credential/{cred_uid}", requests.get.call_args[0][0])

        # not OK status
        verification_response = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            verification_response = vdx_helper.verify_by_credential_uid(cred_uid=cred_uid)
        except VDXError:
            self.assertIsNone(verification_response)
            self.assertEqual(f"{self.url}/verify/credential/{cred_uid}", requests.get.call_args[0][0])

        # with custom mapper
        response.status_code = HTTPStatus.OK
        verification_response = vdx_helper.verify_by_credential_uid(cred_uid=cred_uid, mapper=get_json_mapper())
        self.assertEqual(f"{self.url}/verify/credential/{cred_uid}", requests.get.call_args[0][0])
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
        self.assertEqual(f"{self.url}/certificates", requests.get.call_args[0][0])

        # not OK status
        certificates = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            certificates = vdx_helper.get_certificates()
        except VDXError:
            self.assertIsNone(certificates)
            self.assertEqual(f"{self.url}/certificates", requests.get.call_args[0][0])

        # with custom mapper
        response.status_code = HTTPStatus.OK
        certificates = vdx_helper.get_certificates(mapper=get_json_mapper())
        self.assertEqual(f"{self.url}/certificates", requests.get.call_args[0][0])
        self.assertDictEqual(paginated_certificate, certificates)

    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper.header')
    def test_revoke_certificate(self, header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.post.return_value = response
        cert_uid = UUID("939a9ccb-ddf9-424c-94eb-91898455a968")

        # OK case
        response.status_code = HTTPStatus.OK
        vdx_helper.revoke_certificate(cert_uid=cert_uid)
        self.assertEqual(f"{self.url}/certificates/{cert_uid}/revoke", requests.post.call_args[0][0])

        # not OK case
        response.status_code = HTTPStatus.CONFLICT
        try:
            vdx_helper.revoke_certificate(cert_uid=cert_uid)
        except VDXError:
            self.assertEqual(f"{self.url}/certificates/{cert_uid}/revoke", requests.post.call_args[0][0])

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
        self.assertEqual(f"{self.url}/certificates/{cert_uid}/download", requests.get.call_args[0][0])

        # not OK case
        certificate = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            certificate = vdx_helper.download_certificate(cert_uid=cert_uid)
        except VDXError:
            self.assertIsNone(certificate)
            self.assertEqual(f"{self.url}/certificates/{cert_uid}/download", requests.get.call_args[0][0])

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
        self.assertEqual(f"{self.url}/jobs/{job_uid}/certificates", requests.get.call_args[0][0])

        # not OK status
        certificates = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            certificates = vdx_helper.get_job_certificates(job_uid=job_uid)
        except VDXError:
            self.assertIsNone(certificates)
            self.assertEqual(f"{self.url}/jobs/{job_uid}/certificates", requests.get.call_args[0][0])

        # with custom mapper
        response.status_code = HTTPStatus.OK
        certificates = vdx_helper.get_job_certificates(job_uid=job_uid, mapper=get_json_mapper())
        self.assertEqual(f"{self.url}/jobs/{job_uid}/certificates", requests.get.call_args[0][0])
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
        self.assertEqual(f"{self.url}/jobs/{job_uid}/credentials", requests.get.call_args[0][0])

        # not OK status
        credentials = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            credentials = vdx_helper.get_job_credentials(job_uid=job_uid)
        except VDXError:
            self.assertIsNone(credentials)
            self.assertEqual(f"{self.url}/jobs/{job_uid}/credentials", requests.get.call_args[0][0])

        # with custom mapper
        response.status_code = HTTPStatus.OK
        credentials = vdx_helper.get_job_credentials(job_uid=job_uid, mapper=get_json_mapper())
        self.assertEqual(f"{self.url}/jobs/{job_uid}/credentials", requests.get.call_args[0][0])
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
        # OK status
        response.status_code = HTTPStatus.OK
        job = vdx_helper.schedule_credentials(engine=engine, credentials=credentials)
        self.assertEqual(mapped_job, job)
        self.assertEqual(f"{self.url}/credentials/schedule", requests.post.call_args[0][0])

        # not OK status
        job = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            job = vdx_helper.schedule_credentials(engine=engine, credentials=credentials)
        except VDXError:
            self.assertIsNone(job)
            self.assertEqual(f"{self.url}/credentials/schedule", requests.post.call_args[0][0])

        # with custom mapper
        response.status_code = HTTPStatus.OK
        job = vdx_helper.schedule_credentials(engine=engine, credentials=credentials, mapper=get_json_mapper())
        self.assertEqual(f"{self.url}/credentials/schedule", requests.post.call_args[0][0])
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
        self.assertEqual(f"{self.url}/files", requests.get.call_args[0][0])

        # not OK status
        files = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            files = vdx_helper.get_files()
        except VDXError:
            self.assertIsNone(files)
            self.assertEqual(f"{self.url}/files", requests.get.call_args[0][0])

        # with custom mapper
        response.status_code = HTTPStatus.OK
        files = vdx_helper.get_files(mapper=get_json_mapper())
        self.assertEqual(f"{self.url}/files", requests.get.call_args[0][0])
        self.assertDictEqual(files, paginated_file)

    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper.header')
    def test_get_file_attributes(self, header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.get.return_value = response
        response.json.return_value = file_json
        file_id = "hello_this_is_file_id"
        # OK status
        response.status_code = HTTPStatus.OK
        file_attributes = vdx_helper.get_file_attributes(core_id=file_id)
        self.assertEqual(mapped_file, file_attributes)
        self.assertEqual(f"{self.url}/files/{file_id}/attributes", requests.get.call_args[0][0])

        # not OK status
        file_attributes = None
        response.status_code = HTTPStatus.CONFLICT
        try:
            file_attributes = vdx_helper.get_file_attributes(core_id=file_id)
        except VDXError:
            self.assertIsNone(file_attributes)
            self.assertEqual(f"{self.url}/files/{file_id}/attributes", requests.get.call_args[0][0])

        # with custom mapper
        response.status_code = HTTPStatus.OK
        file_attributes = vdx_helper.get_file_attributes(core_id=file_id, mapper=get_json_mapper())
        self.assertEqual(f"{self.url}/files/{file_id}/attributes", requests.get.call_args[0][0])
        self.assertDictEqual(file_attributes, file_json)

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
        self.assertEqual(f"{self.url}/jobs", requests.patch.call_args[0][0])

        # not OK case
        response.status_code = HTTPStatus.CONFLICT
        try:
            vdx_helper.update_job_tags(updated_job_tags=updated_job_tags)
        except VDXError:
            self.assertEqual(f"{self.url}/jobs", requests.patch.call_args[0][0])

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
        self.assertEqual(f"{self.url}/jobs", requests.put.call_args[0][0])

        # not OK case
        response.status_code = HTTPStatus.CONFLICT
        try:
            vdx_helper.replace_job_tags(replace_job_tags=replace_job_tags)
        except VDXError:
            self.assertEqual(f"{self.url}/jobs", requests.put.call_args[0][0])

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
        self.assertEqual(f"{self.url}/credentials", requests.patch.call_args[0][0])

        # not OK case
        response.status_code = HTTPStatus.CONFLICT
        try:
            vdx_helper.update_credential_tags(updated_credential_tags=updated_credential_tags)
        except VDXError:
            self.assertEqual(f"{self.url}/credentials", requests.patch.call_args[0][0])

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
        self.assertEqual(f"{self.url}/credentials", requests.put.call_args[0][0])

        # not OK case
        response.status_code = HTTPStatus.CONFLICT
        try:
            vdx_helper.replace_credential_tags(replace_credential_tags=replace_credential_tags)
        except VDXError:
            self.assertEqual(f"{self.url}/credentials", requests.put.call_args[0][0])

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
        self.assertEqual(f"{self.url}/credentials/{cred_uid}/delete_tag", requests.patch.call_args[0][0])

        # not OK case
        response.status_code = HTTPStatus.CONFLICT
        try:
            vdx_helper.delete_credential_tag(cred_uid=cred_uid, tag=credential_tag)
        except VDXError:
            self.assertEqual(f"{self.url}/credentials/{cred_uid}/delete_tag", requests.patch.call_args[0][0])
