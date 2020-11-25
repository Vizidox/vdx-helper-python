from unittest.mock import patch

from pytest import raises
from unittest import TestCase
from testcontainers.compose import DockerCompose
from os import path

from vdx_helper import VDXHelper


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
    def test_get_cost(self, _get_token_string) -> None:
        _get_token_string.return_value = "vizidox-authorization"
        vdx_helper = self.get_vdx_helper()
        permissions = vdx_helper.get_partner_permissions()
        assert permissions is not None
