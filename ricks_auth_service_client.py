from typing import Dict

import aiohttp

ALLOWED_FLOWS = ["otp", "magic"]


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


class InvalidAuthFlow(AuthClientError):
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

    async def authenticate(self, email, flow="otp") -> str:
        """Initialize authentication flow for user email

        :param email: user's email address
        :param flow: which authentication flow to use. Defaults to otp
        :return: Message from server
        :raises AppNotFound: if the app id is invalid.
        :raises ServerError: if something goes wrong on the server.
        :raises ValidationError: if something is wrong with the request.
        """
        if flow not in ALLOWED_FLOWS:
            raise InvalidAuthFlow
        return await _perform_post(
            f"{self.host}/{flow}/request/{self.app_id}", {"email": email}
        )

    async def submit_code(self, email: str, code) -> Dict[str, str]:
        """Submit an authentication code and get a token back

        :param email: User's email address.
        :param code: Submitted one time password code.
        :returns: Dict containing id_token and refresh_token or None if refresh
        is not enabled
        :raises AppNotFound: if the app id is invalid (cannot be found).
        :raises ServerError: if something goes wrong on the server.
        :raises ValidationError: if something is wrong with the request data.
        :raises AuthenticationFailure: if the email code combination doesn't authenticate.
        """
        data = await _perform_post(
            f"{self.host}/otp/confirm/{self.app_id}", {"email": email, "code": code}
        )
        try:
            return {
                "id_token": data["idToken"],
                "refresh_token": data.get("refreshToken"),
            }
        except (KeyError, TypeError):
            raise AuthClientError("idToken was not in response")

    async def verify_token_remote(self, id_token: str) -> Dict[str, dict]:
        """Request the server to verify an idToken for you.
        :param id_token: JWT idToken from client

        :returns: Dict of headers and claims from the verified JWT
        :raises ValidationError: If the request was invalid in some way
        :raises AuthenticationFailure: If the token could not be verified
        :raises AppNotFound: Not found from server, the app does not exist.
        :raises ServerError: The server experienced an error.
        """
        data = await _perform_post(
            f"{self.host}/token/verify/{self.app_id}", {"idToken": id_token}
        )
        if not data or "headers" not in data or "claims" not in data:
            raise AuthenticationFailure("Data missing from response")
        return data

    async def refresh(self, refresh_token: str) -> str:
        """Request a new ID Token using a refresh token.
        :param refresh_token: Refresh token from a client.

        :returns: New ID Token
        :raises ValidationError: If the request was invalid in some way
        :raises AuthenticationFailure: If the token could not be verified
        :raises AppNotFound: Not found from server, the app does not exist.
        :raises ServerError: The server experienced an error.
        """
        data = await _perform_post(
            f"{self.host}/token/refresh/{self.app_id}", {"refreshToken": refresh_token}
        )
        try:
            return data["idToken"]
        except (TypeError, KeyError):
            raise AuthenticationFailure("ID token not in response")

    async def app_info(self) -> dict:
        """Get full info about this app
        :returns: dict of info about the app

        :raises AppNotFound: Not found from server, the app does not exist.
        :raises ServerError: The server experienced an error.
        """
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{self.host}/app/{self.app_id}") as response:
                _check_response(response)
                return await response.json()


async def _perform_post(url: str, body: dict):
    async with aiohttp.ClientSession() as session:
        async with session.post(url, json=body) as response:
            _check_response(response)
            return await response.json()
