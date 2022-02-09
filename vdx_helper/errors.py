from http import HTTPStatus

from requests import Response


class VDXError(Exception):
    """
    An exception class representing any error returned by the VDX Core API. It contains the respective
    status code as well as the corresponding error message

    :param code: The status code
    :type code: :class:`http.HTTPStatus`

    :param message: The error message
    :type message: str
    """

    def __init__(self, code: HTTPStatus, message: str):
        self.code = code
        self.message = message


def error_from_response(status: HTTPStatus, response: Response):
    """
    Maps a given error from an endpoint response to an exception with the correct status code and description of the
    error

    :param status: The status code of the endpoint response
    :type status: HTTPStatus

    :param response: The endpoint response
    :type response: :class:`requests.Response`

    :return: A VDXError to be raised
    :rtype: :class:`VDXError`
    """
    if status is not HTTPStatus.OK:
        try:
            json_response = response.json()
            description = json_response.get("description")
        except (ValueError, AttributeError):
            description = ""
        return VDXError(code=status, message=description)
