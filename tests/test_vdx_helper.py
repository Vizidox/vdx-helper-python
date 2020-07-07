from http import HTTPStatus
from vdx_helper.vdx_helper import VDXHelper, VDXError
from unittest.mock import patch, MagicMock
from typing import Dict, Any, Callable
import requests
import unittest
import copy

Json = Dict[str, Any]
class VdxHelperTest(unittest.TestCase):
    def setUp(self):
        self.url = "vizidox.com"
        self.keycloak_url = "vizidox-keycloak.com"
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
        self.assertEqual(token_expiration_date, self.default_current_time+50)
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
    def test_get_request_header(self, _get_token_string):
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
    def test_upload_file(self, requests, header):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        #file
        filename = "name"
        stream = MagicMock()
        content_type = "content_type"

        #response
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
        
        # default mapper
        response.status_code = HTTPStatus.OK
        json_result = vdx_helper.upload_file(filename, stream, content_type, mapper=get_json_mapper())
        self.assertDictEqual(json_result, file_json)
        file_info = requests.post.call_args[1]['files']['file']
        self.assertEqual(file_info[0], "name")
        self.assertEqual(file_info[2], "content_type")
        
    @patch('vdx_helper.vdx_helper.VDXHelper._get_request_header')
    @patch('vdx_helper.vdx_helper.VDXHelper._compute_core_file_id')
    @patch('vdx_helper.vdx_helper.requests')
    def test_update_file_attributes(self, requests, _compute_core_file_id, _get_request_header):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        _compute_core_file_id.return_value = 'abc'
        file_summary = MagicMock()
        filename = 'vizidox'

        #response
        response.status_code = HTTPStatus.OK
        requests.put.return_value = response
        
        # encrypted_hash case
        file_summary.encrypted_hash = "encrypted_hash"
        file_summary.file_hash = "file_hash"
        status = vdx_helper.update_file_attributes(file_summary=file_summary, filename=filename)
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(f"{self.url}/files/abc/attributes", requests.put.call_args[0][0])
        self.assertEqual(_compute_core_file_id.call_args[0][0], "encrypted_hash")
        
        # file_hash case
        file_summary.encrypted_hash = None
        file_summary.file_hash = "file_hash"
        status = vdx_helper.update_file_attributes(file_summary=file_summary, filename=filename)
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(f"{self.url}/files/abc/attributes", requests.put.call_args[0][0])
        self.assertEqual(_compute_core_file_id.call_args[0][0], "file_hash")
    
    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.io')
    @patch('vdx_helper.vdx_helper.VDXHelper._get_request_header')
    def test_download_credential_file(self, _get_request_header, io, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.get.return_value = response
        io.BytesIO.return_value = "document_file"
        doc_uid = 'doc_uid'
        
        # OK case
        response.status_code = HTTPStatus.OK
        status, document_file = vdx_helper.download_credential_file(doc_uid)
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual("document_file", document_file)
        self.assertEqual(f"{self.url}/credentials/{doc_uid}/file", requests.get.call_args[0][0])
        
        # not OK case
        response.status_code = HTTPStatus.CONFLICT
        status, document_file = vdx_helper.download_credential_file(doc_uid)
        self.assertEqual(status, HTTPStatus.CONFLICT)
        self.assertIsNone(document_file)
        self.assertEqual(f"{self.url}/credentials/{doc_uid}/file", requests.get.call_args[0][0])
        
    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper._get_pagination_params')
    @patch('vdx_helper.vdx_helper.VDXHelper._get_request_header')
    def test_get_credentials(self, _get_request_header, _get_pagination_params, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.get.return_value = response
        response.json.return_value = self.default_json_value
        
        # OK case
        response.status_code = HTTPStatus.OK
        status, document_file = vdx_helper.get_credentials()
        self.assertEqual(status, HTTPStatus.OK)
        self.assertDictEqual(self.default_json_value, document_file)
        self.assertEqual(f"{self.url}/credentials", requests.get.call_args[0][0])
        
        # not OK case
        response.status_code = HTTPStatus.CONFLICT
        status, document_file = vdx_helper.get_credentials()
        self.assertEqual(status, HTTPStatus.CONFLICT)
        self.assertIsNone(document_file)
        self.assertEqual(f"{self.url}/credentials", requests.get.call_args[0][0])
        
        # with custom mapper
        response.status_code = HTTPStatus.OK
        status, document_file = vdx_helper.get_credentials(self.new_mapper())
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(f"{self.url}/credentials", requests.get.call_args[0][0])
        self.assertDictEqual(document_file, self.new_mapper()(self.default_json_value))
        
    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper._get_pagination_params')
    @patch('vdx_helper.vdx_helper.VDXHelper._get_request_header')
    def test_get_credential(self, _get_request_header, _get_pagination_params, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.get.return_value = response
        response.json.return_value = self.default_json_value
        cred_uid = 'vizidox-random-UUID'
        
        # OK case
        response.status_code = HTTPStatus.OK
        status, document_file = vdx_helper.get_credential(cred_uid=cred_uid)
        self.assertEqual(status, HTTPStatus.OK)
        self.assertDictEqual(self.default_json_value, document_file)
        self.assertEqual(f"{self.url}/credentials/{cred_uid}", requests.get.call_args[0][0])
        
        # not OK case
        response.status_code = HTTPStatus.CONFLICT
        status, document_file = vdx_helper.get_credential(cred_uid=cred_uid)
        self.assertEqual(status, HTTPStatus.CONFLICT)
        self.assertIsNone(document_file)
        self.assertEqual(f"{self.url}/credentials/{cred_uid}", requests.get.call_args[0][0])
        
        # with custom mapper
        response.status_code = HTTPStatus.OK
        status, document_file = vdx_helper.get_credential(cred_uid=cred_uid, mapper=self.new_mapper())
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(f"{self.url}/credentials/{cred_uid}", requests.get.call_args[0][0])
        self.assertDictEqual(document_file, self.new_mapper()(self.default_json_value))
        
        
    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper._get_request_header')
    @patch('vdx_helper.vdx_helper.VDXHelper._compute_core_file_id')
    def test_create_credential(self, _compute_core_file_id, _get_request_header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.post.return_value = response
        response.json.return_value = self.default_json_value
        file_summary = MagicMock()

        title = 'title'
        metadata = 'metadata'

        _compute_core_file_id.return_value = 'core_id'
        
        # OK case with encrypted_hash
        file_summary.encrypted_hash = 'encrypted_hash'
        file_summary.file_hash = 'file_hash'
        response.status_code = HTTPStatus.OK
        status, credential = vdx_helper.create_credential(title=title, file_summary=file_summary, metadata=metadata)
        self.assertEqual(status, HTTPStatus.OK)
        self.assertDictEqual(self.default_json_value, credential)
        self.assertEqual(f"{self.url}/credentials", requests.post.call_args[0][0])
        self.assertDictEqual({'title': title, 'metadata': metadata, 'file_id': 'core_id'}, requests.post.call_args[1]['json'])
        self.assertEqual(_compute_core_file_id.call_args[0][0], 'encrypted_hash')
        
        # OK case encrypted_hash
        response.status_code = HTTPStatus.CONFLICT
        status, credential = vdx_helper.create_credential(title=title, file_summary=file_summary, metadata=metadata)
        self.assertEqual(status, HTTPStatus.CONFLICT)
        self.assertIsNone(credential)
        self.assertEqual(f"{self.url}/credentials", requests.post.call_args[0][0])
        self.assertDictEqual({'title': title, 'metadata': metadata, 'file_id': 'core_id'}, requests.post.call_args[1]['json'])
        self.assertEqual(_compute_core_file_id.call_args[0][0], 'encrypted_hash')

        # not OK case with file_hash
        file_summary.encrypted_hash = None
        response.status_code = HTTPStatus.OK
        status, credential = vdx_helper.create_credential(title=title, file_summary=file_summary, metadata=metadata)
        self.assertEqual(status, HTTPStatus.OK)
        self.assertDictEqual(self.default_json_value, credential)
        self.assertEqual(f"{self.url}/credentials", requests.post.call_args[0][0])
        self.assertDictEqual({'title': title, 'metadata': metadata, 'file_id': 'core_id'}, requests.post.call_args[1]['json'])
        self.assertEqual(_compute_core_file_id.call_args[0][0], 'file_hash')
        
        # not OK case file_hash
        response.status_code = HTTPStatus.CONFLICT
        status, credential = vdx_helper.create_credential(title=title, file_summary=file_summary, metadata=metadata)
        self.assertEqual(status, HTTPStatus.CONFLICT)
        self.assertIsNone(credential)
        self.assertEqual(f"{self.url}/credentials", requests.post.call_args[0][0])
        self.assertDictEqual({'title': title, 'metadata': metadata, 'file_id': 'core_id'}, requests.post.call_args[1]['json'])
        self.assertEqual(_compute_core_file_id.call_args[0][0], 'file_hash')
        
        # with custom mapper
        file_summary.encrypted_hash = 'encrypted_hash'
        file_summary.file_hash = 'file_hash'
        response.status_code = HTTPStatus.OK
        status, credential = vdx_helper.create_credential(title=title, file_summary=file_summary, metadata=metadata, mapper=self.new_mapper())
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(f"{self.url}/credentials", requests.post.call_args[0][0])
        self.assertDictEqual({'title': title, 'metadata': metadata, 'file_id': 'core_id'}, requests.post.call_args[1]['json'])
        self.assertEqual(_compute_core_file_id.call_args[0][0], 'encrypted_hash')
        self.assertDictEqual(credential, self.new_mapper()(self.default_json_value))
    
    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper._get_request_header')
    def test_issue_job(self, _get_request_header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.post.return_value = response
        response.json.return_value = self.default_json_value
        engine = 'engine'
        credentials = ['credential1', 'credential2']
        expiry_date = '12/15/2019'
        # OK status
        response.status_code = HTTPStatus.OK
        status, job = vdx_helper.issue_job(engine=engine, credentials=credentials, expiry_date=expiry_date)
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(self.default_json_value, job)
        self.assertEqual(f"{self.url}/jobs", requests.post.call_args[0][0])
        
        # not OK status
        response.status_code = HTTPStatus.CONFLICT
        status, job = vdx_helper.issue_job(engine=engine, credentials=credentials, expiry_date=expiry_date)
        self.assertEqual(status, HTTPStatus.CONFLICT)
        self.assertIsNone(job)
        self.assertEqual(f"{self.url}/jobs", requests.post.call_args[0][0])
        
        # with custom mapper
        response.status_code = HTTPStatus.OK
        status, job = vdx_helper.issue_job(engine=engine, credentials=credentials, expiry_date=expiry_date, mapper=self.new_mapper())
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(f"{self.url}/jobs", requests.post.call_args[0][0])
        self.assertDictEqual(job, self.new_mapper()(self.default_json_value))
        
    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper._get_request_header')
    def test_get_job(self, _get_request_header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.get.return_value = response
        response.json.return_value = self.default_json_value
        job_uid = 'vizidox-random-uuid'
        # OK status
        response.status_code = HTTPStatus.OK
        status, job = vdx_helper.get_job(job_uid)
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(self.default_json_value, job)
        self.assertEqual(f"{self.url}/jobs/{job_uid}", requests.get.call_args[0][0])
        
        # not OK status
        response.status_code = HTTPStatus.CONFLICT
        status, job = vdx_helper.get_job(job_uid)
        self.assertEqual(status, HTTPStatus.CONFLICT)
        self.assertIsNone(job)
        self.assertEqual(f"{self.url}/jobs/{job_uid}", requests.get.call_args[0][0])
        
        # with custom mapper
        response.status_code = HTTPStatus.OK
        status, job = vdx_helper.get_job(job_uid=job_uid, mapper=self.new_mapper())
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(f"{self.url}/jobs/{job_uid}", requests.get.call_args[0][0])
        self.assertDictEqual(job, self.new_mapper()(self.default_json_value))

    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper._get_request_header')
    @patch('vdx_helper.vdx_helper.VDXHelper._get_pagination_params')
    def test_get_jobs(self, _get_pagination_params, _get_request_header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.get.return_value = response
        response.json.return_value = self.default_json_value
        # OK status
        response.status_code = HTTPStatus.OK
        status, job = vdx_helper.get_jobs()
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(self.default_json_value, job)
        self.assertEqual(f"{self.url}/jobs", requests.get.call_args[0][0])
        
        # not OK status
        response.status_code = HTTPStatus.CONFLICT
        status, job = vdx_helper.get_jobs()
        self.assertEqual(status, HTTPStatus.CONFLICT)
        self.assertIsNone(job)
        self.assertEqual(f"{self.url}/jobs", requests.get.call_args[0][0])
        
        # with custom mapper
        response.status_code = HTTPStatus.OK
        status, job = vdx_helper.get_jobs(mapper=self.new_mapper())
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(f"{self.url}/jobs", requests.get.call_args[0][0])
        self.assertDictEqual(job, self.new_mapper()(self.default_json_value))

    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper._get_request_header')
    def test_verify_by_uid(self, _get_request_header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.get.return_value = response
        response.json.return_value = self.default_json_value
        
        cert_uid = 'vizidox-random-uuid'
        # OK status
        response.status_code = HTTPStatus.OK
        status, verification_response = vdx_helper.verify_by_uid(cert_uid)
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(self.default_json_value, verification_response)
        self.assertEqual(f"{self.url}/verify/{cert_uid}", requests.get.call_args[0][0])
        
        # not OK status
        response.status_code = HTTPStatus.CONFLICT
        status, verification_response = vdx_helper.verify_by_uid(cert_uid)
        self.assertEqual(status, HTTPStatus.CONFLICT)
        self.assertIsNone(verification_response)
        self.assertEqual(f"{self.url}/verify/{cert_uid}", requests.get.call_args[0][0])
        
        # with custom mapper
        response.status_code = HTTPStatus.OK
        status, verification_response = vdx_helper.verify_by_uid(cert_uid=cert_uid, mapper=self.new_mapper())
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(f"{self.url}/verify/{cert_uid}", requests.get.call_args[0][0])
        self.assertDictEqual(verification_response, self.new_mapper()(self.default_json_value))
        
    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper._get_request_header')
    def test_verify_by_certificate(self, _get_request_header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.post.return_value = response
        response.json.return_value = self.default_json_value
        
        cert_uid = 'vizidox-random-uuid'
        #file
        file_ = MagicMock()
        file_.filename = "file_name"
        file_.content_type = "content_type"
        # OK status
        response.status_code = HTTPStatus.OK
        status, verification_response = vdx_helper.verify_by_certificate(file=file_)
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(self.default_json_value, verification_response)
        self.assertEqual(f"{self.url}/verify/upload/certificate", requests.post.call_args[0][0])
        
        # not OK status
        response.status_code = HTTPStatus.CONFLICT
        status, verification_response = vdx_helper.verify_by_certificate(file=file_)
        self.assertEqual(status, HTTPStatus.CONFLICT)
        self.assertIsNone(verification_response)
        self.assertEqual(f"{self.url}/verify/upload/certificate", requests.post.call_args[0][0])
        
        # with custom mapper
        response.status_code = HTTPStatus.OK
        status, verification_response = vdx_helper.verify_by_certificate(file=file_, mapper=self.new_mapper())
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(f"{self.url}/verify/upload/certificate", requests.post.call_args[0][0])
        self.assertDictEqual(verification_response, self.new_mapper()(self.default_json_value))
        
    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper._get_request_header')
    def test_verify_by_file(self, _get_request_header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.post.return_value = response
        response.json.return_value = self.default_json_value
        
        cert_uid = 'vizidox-random-uuid'
        #file
        file_ = MagicMock()
        file_.filename = "file_name"
        file_.content_type = "content_type"
        # OK status
        response.status_code = HTTPStatus.OK
        status, verification_response = vdx_helper.verify_by_file(file=file_)
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(self.default_json_value, verification_response)
        self.assertEqual(f"{self.url}/verify/upload/file", requests.post.call_args[0][0])
        
        # not OK status
        response.status_code = HTTPStatus.CONFLICT
        status, verification_response = vdx_helper.verify_by_file(file=file_)
        self.assertEqual(status, HTTPStatus.CONFLICT)
        self.assertIsNone(verification_response)
        self.assertEqual(f"{self.url}/verify/upload/file", requests.post.call_args[0][0])
        
        # with custom mapper
        response.status_code = HTTPStatus.OK
        status, verification_response = vdx_helper.verify_by_file(file=file_, mapper=self.new_mapper())
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(f"{self.url}/verify/upload/file", requests.post.call_args[0][0])
        self.assertDictEqual(verification_response, self.new_mapper()(self.default_json_value))

    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper._get_request_header')
    @patch('vdx_helper.vdx_helper.VDXHelper._get_pagination_params')
    def test_get_certificates(self, _get_pagination_params, _get_request_header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.get.return_value = response
        response.json.return_value = self.default_json_value
        cert_uid = 'vizidox-random-uuid'
        #file
        file_ = MagicMock()
        file_.filename = "file_name"
        file_.content_type = "content_type"
        # OK status
        response.status_code = HTTPStatus.OK
        status, verification_response = vdx_helper.get_certificates()
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(self.default_json_value, verification_response)
        self.assertEqual(f"{self.url}/certificates", requests.get.call_args[0][0])
        
        # not OK status
        response.status_code = HTTPStatus.CONFLICT
        status, verification_response = vdx_helper.get_certificates()
        self.assertEqual(status, HTTPStatus.CONFLICT)
        self.assertIsNone(verification_response)
        self.assertEqual(f"{self.url}/certificates", requests.get.call_args[0][0])
        
        # with custom mapper
        response.status_code = HTTPStatus.OK
        status, verification_response = vdx_helper.get_certificates(mapper=self.new_mapper())
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(f"{self.url}/certificates", requests.get.call_args[0][0])
        self.assertDictEqual(verification_response, self.new_mapper()(self.default_json_value))
    
    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper._get_request_header')
    def test_revoke_certificate(self, _get_request_header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.post.return_value = response
        cert_uid = 'vizidox-random-uuid'
        
        # OK case
        response.status_code = HTTPStatus.OK
        status = vdx_helper.revoke_certificate(cert_uid=cert_uid)
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(f"{self.url}/certificates/{cert_uid}/revoke", requests.post.call_args[0][0])
        
        # not OK case
        response.status_code = HTTPStatus.CONFLICT
        status = vdx_helper.revoke_certificate(cert_uid=cert_uid)
        self.assertEqual(status, HTTPStatus.CONFLICT)
        self.assertEqual(f"{self.url}/certificates/{cert_uid}/revoke", requests.post.call_args[0][0])
        
    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.io')
    @patch('vdx_helper.vdx_helper.VDXHelper._get_request_header')
    def test_download_certificate(self, _get_request_header, io, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.get.return_value = response
        io.BytesIO.return_value = "certificate"
        cert_uid = 'vizidox-random-uuid'
        
        # OK case
        response.status_code = HTTPStatus.OK
        status, certificate = vdx_helper.download_certificate(cert_uid=cert_uid)
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual("certificate", certificate)
        self.assertEqual(f"{self.url}/certificates/{cert_uid}/download", requests.get.call_args[0][0])
        
        # not OK case
        response.status_code = HTTPStatus.CONFLICT
        status, certificate = vdx_helper.download_certificate(cert_uid=cert_uid)
        self.assertEqual(status, HTTPStatus.CONFLICT)
        self.assertIsNone(certificate)
        self.assertEqual(f"{self.url}/certificates/{cert_uid}/download", requests.get.call_args[0][0])

    @patch('vdx_helper.vdx_helper.requests')
    @patch('vdx_helper.vdx_helper.VDXHelper._get_request_header')
    @patch('vdx_helper.vdx_helper.VDXHelper._get_pagination_params')
    def test_get_job_certificates(self, _get_pagination_params, _get_request_header, requests):
        vdx_helper = self.get_vdx_helper()
        response = MagicMock()
        requests.get.return_value = response
        response.json.return_value = self.default_json_value
        job_uid = 'vizidox-random-uuid'
        #file
        file_ = MagicMock()
        file_.filename = "file_name"
        file_.content_type = "content_type"
        # OK status
        response.status_code = HTTPStatus.OK
        status, verification_response = vdx_helper.get_job_certificates(job_uid=job_uid)
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(self.default_json_value, verification_response)
        self.assertEqual(f"{self.url}/jobs/{job_uid}/certificates", requests.get.call_args[0][0])
        
        # not OK status
        response.status_code = HTTPStatus.CONFLICT
        status, verification_response = vdx_helper.get_job_certificates(job_uid=job_uid)
        self.assertEqual(status, HTTPStatus.CONFLICT)
        self.assertIsNone(verification_response)
        self.assertEqual(f"{self.url}/jobs/{job_uid}/certificates", requests.get.call_args[0][0])
        
        # with custom mapper
        response.status_code = HTTPStatus.OK
        status, verification_response = vdx_helper.get_job_certificates(job_uid=job_uid, mapper=self.new_mapper())
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(f"{self.url}/jobs/{job_uid}/certificates", requests.get.call_args[0][0])
        self.assertDictEqual(verification_response, self.new_mapper()(self.default_json_value))
    
    @patch('vdx_helper.vdx_helper.request')
    def test_get_pagination_params(self, request):
        args = {
            'filterby': 'filterby',
            'sortby': 'sortby',
            'order': 'order'
        }
        request.args = args
        pagi_params = VDXHelper._get_pagination_params()
        args.update({'count': 0, 'page': 1})
        self.assertDictEqual(args, pagi_params)
        