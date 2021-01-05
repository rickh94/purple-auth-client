from typing import Dict

import aiohttp


class AuthClientError(Exception):
    pass


class AppNotFound(AuthClientError):
    pass


class ServerError(AuthClientError):
    pass


class ValidationError(AuthClientError):
    pass


class AuthenticationFailure(AuthClientError):
    pass


def _check_response(response):
    if response.status == 200:
        return
    if response.status == 404:
        raise AppNotFound
    if response.status == 500:
        raise ServerError
    if response.status == 422:
        raise ValidationError
    if response.status == 401 or response.status == 403:
        raise AuthenticationFailure


class AuthClient:
    def __init__(self, host: str, app_id: str):
        """Create the auth client objects

        :param host: hostname of the auth server without 'https://'
        :param app_id: The unique ID of the app to authenticate against.
        """
        self.host = "https://" + host
        self.app_id = app_id
        self._public_key = None

    async def authenticate(self, email) -> str:
        """Initialize authentication flow for user email

        :param email: user's email address
        :return: Message from server
        :raises AppNotFound: if the app id is invalid.
        :raises ServerError: if something goes wrong on the server.
        :raises ValidationError: if something is wrong with the request.
        """
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.host}/otp/request/{self.app_id}",
                json={"email": email},
            ) as response:
                _check_response(response)
                return await response.json()

    async def submit_code(self, email: str, code) -> Dict[str, str]:
        """Submit an authentication code and get a token back

        :param email: User's email address.
        :param code: Submitted one time password code.
        :returns: Dict containing id_token
        :raises AppNotFound: if the app id is invalid (cannot be found).
        :raises ServerError: if something goes wrong on the server.
        :raises ValidationError: if something is wrong with the request data.
        :raises AuthenticationFailure: if the email code combination doesn't authenticate.
        """
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.host}/otp/confirm/{self.app_id}",
                json={"email": email, "code": code},
            ) as response:
                _check_response(response)
                data = await response.json()
                try:
                    return {"id_token": data["idToken"]}
                except KeyError:
                    raise AuthClientError("idToken was not in response")
