import datetime

import pytest
from aioresponses import aioresponses
from faker import Faker
from jwcrypto import jwk
import python_jwt as jwt

from purple_auth_client import (
    AuthClient,
    AppNotFound,
    ServerError,
    ValidationError,
    AuthenticationFailure,
    AuthClientError,
    InvalidAuthFlow,
)


@pytest.fixture
def auth_client():
    return AuthClient("http://auth.example.com", "123456", "testkey")


@pytest.fixture
def mock_aioresponse():
    with aioresponses() as m:
        yield m


@pytest.fixture
def fake_email():
    return Faker().email()


@pytest.fixture
def fake_name():
    return Faker().company()


@pytest.fixture
def test_code():
    return "11111111"


@pytest.fixture
def fake_token():
    return "this-is-a-fake-jwt"


@pytest.fixture
def fake_refresh_token():
    return "this-is-a-fake-refresh-token"


@pytest.fixture
def fake_key(mock_aioresponse, auth_client):
    _key = jwk.JWK.generate(kty="EC", size=2048)
    mock_aioresponse.get(
        f"{auth_client.host}/app/public_key/{auth_client.app_id}",
        status=200,
        payload=_key.export_public(as_dict=True),
    )
    return _key


@pytest.fixture
def valid_token(fake_email, fake_key):
    return jwt.generate_jwt(
        {"sub": fake_email}, fake_key, "ES256", datetime.timedelta(minutes=30)
    )


@pytest.fixture
def invalid_token(fake_email):
    other_key = jwk.JWK.generate(kty="EC", size=2048)
    return jwt.generate_jwt(
        {"sub": fake_email}, other_key, "ES256", datetime.timedelta(minutes=30)
    )


@pytest.fixture
def expired_token(fake_email, fake_key):
    return jwt.generate_jwt(
        {"sub": fake_email}, fake_key, "ES256", datetime.timedelta(minutes=0)
    )


def test_create():
    client = AuthClient("localhost", "12345", "testkey")
    assert client.host == "https://localhost"
    assert client.app_id == "12345"
    assert client._public_key is None


@pytest.mark.asyncio
async def test_authenticate_success(mock_aioresponse, auth_client, fake_email):
    mock_aioresponse.post(
        f"{auth_client.host}/otp/request/{auth_client.app_id}",
        status=200,
        payload="Response message from server",
    )

    output = await auth_client.authenticate(fake_email)
    assert output == "Response message from server"

    request_args = list(mock_aioresponse.requests.values())[0][0].kwargs
    assert request_args["json"]["email"] == fake_email


@pytest.mark.asyncio
async def test_authenticate_otp(mock_aioresponse, auth_client, fake_email):
    mock_aioresponse.post(
        f"{auth_client.host}/otp/request/{auth_client.app_id}",
        status=200,
        payload="Response message from server",
    )

    output = await auth_client.authenticate(fake_email, flow="otp")
    assert output == "Response message from server"

    request_args = list(mock_aioresponse.requests.values())[0][0].kwargs
    assert request_args["json"]["email"] == fake_email


@pytest.mark.asyncio
async def test_authenticate_magic(mock_aioresponse, auth_client, fake_email):
    mock_aioresponse.post(
        f"{auth_client.host}/magic/request/{auth_client.app_id}",
        status=200,
        payload="Response message from server",
    )

    output = await auth_client.authenticate(fake_email, flow="magic")
    assert output == "Response message from server"

    request_args = list(mock_aioresponse.requests.values())[0][0].kwargs
    assert request_args["json"]["email"] == fake_email


@pytest.mark.asyncio
async def test_authenticate_invalid_flow(auth_client, fake_email):
    with pytest.raises(InvalidAuthFlow):
        await auth_client.authenticate(fake_email, flow="not_real")


@pytest.mark.asyncio
async def test_authenticate_not_found(mock_aioresponse, auth_client, fake_email):
    mock_aioresponse.post(
        f"{auth_client.host}/otp/request/{auth_client.app_id}",
        status=404,
    )
    with pytest.raises(AppNotFound):
        await auth_client.authenticate(fake_email)


@pytest.mark.asyncio
async def test_authenticate_server_error(mock_aioresponse, auth_client, fake_email):
    mock_aioresponse.post(
        f"{auth_client.host}/otp/request/{auth_client.app_id}",
        status=500,
    )
    with pytest.raises(ServerError):
        await auth_client.authenticate(fake_email)


@pytest.mark.asyncio
async def test_authenticate_validation_error(mock_aioresponse, auth_client, fake_email):
    mock_aioresponse.post(
        f"{auth_client.host}/otp/request/{auth_client.app_id}",
        status=422,
    )
    with pytest.raises(ValidationError):
        await auth_client.authenticate(fake_email)


@pytest.mark.asyncio
async def test_submit_code_success(
    mock_aioresponse, auth_client, fake_email, test_code
):
    mock_aioresponse.post(
        f"{auth_client.host}/otp/confirm/{auth_client.app_id}",
        status=200,
        payload={"idToken": "fake-id-token"},
    )

    output = await auth_client.submit_code(fake_email, test_code)

    assert output == {"id_token": "fake-id-token", "refresh_token": None}

    request_args = list(mock_aioresponse.requests.values())[0][0].kwargs
    assert request_args["json"]["email"] == fake_email
    assert request_args["json"]["code"] == test_code


@pytest.mark.asyncio
async def test_submit_code_success_with_refresh(
    mock_aioresponse, auth_client, fake_email, test_code
):
    mock_aioresponse.post(
        f"{auth_client.host}/otp/confirm/{auth_client.app_id}",
        status=200,
        payload={"idToken": "fake-id-token", "refreshToken": "fake-refresh-token"},
    )

    output = await auth_client.submit_code(fake_email, test_code)

    assert output == {
        "id_token": "fake-id-token",
        "refresh_token": "fake-refresh-token",
    }

    request_args = list(mock_aioresponse.requests.values())[0][0].kwargs
    assert request_args["json"]["email"] == fake_email
    assert request_args["json"]["code"] == test_code


@pytest.mark.asyncio
async def test_submit_code_not_found(
    mock_aioresponse, auth_client, fake_email, test_code
):
    mock_aioresponse.post(
        f"{auth_client.host}/otp/confirm/{auth_client.app_id}",
        status=404,
    )

    with pytest.raises(AppNotFound):
        await auth_client.submit_code(fake_email, test_code)


@pytest.mark.asyncio
async def test_submit_code_validation_error(
    mock_aioresponse, auth_client, fake_email, test_code
):
    mock_aioresponse.post(
        f"{auth_client.host}/otp/confirm/{auth_client.app_id}",
        status=422,
    )

    with pytest.raises(ValidationError):
        await auth_client.submit_code(fake_email, test_code)


@pytest.mark.asyncio
async def test_submit_code_server_error(
    mock_aioresponse, auth_client, fake_email, test_code
):
    mock_aioresponse.post(
        f"{auth_client.host}/otp/confirm/{auth_client.app_id}",
        status=500,
    )

    with pytest.raises(ServerError):
        await auth_client.submit_code(fake_email, test_code)


@pytest.mark.asyncio
async def test_submit_code_authentication_failed(
    mock_aioresponse, auth_client, fake_email, test_code
):
    mock_aioresponse.post(
        f"{auth_client.host}/otp/confirm/{auth_client.app_id}",
        status=401,
    )

    with pytest.raises(AuthenticationFailure):
        await auth_client.submit_code(fake_email, test_code)


@pytest.mark.asyncio
async def test_submit_code_missing_response_from_server(
    mock_aioresponse, auth_client, fake_email, test_code
):
    mock_aioresponse.post(
        f"{auth_client.host}/otp/confirm/{auth_client.app_id}",
        status=200,
    )

    with pytest.raises(AuthClientError):
        await auth_client.submit_code(fake_email, test_code)


@pytest.mark.asyncio
async def test_submit_code_missing_token_in_response(
    mock_aioresponse, auth_client, fake_email, test_code
):
    mock_aioresponse.post(
        f"{auth_client.host}/otp/confirm/{auth_client.app_id}",
        status=200,
        payload={"nothing": "useful"},
    )

    with pytest.raises(AuthClientError):
        await auth_client.submit_code(fake_email, test_code)


@pytest.mark.asyncio
async def test_verify_token_remote(
    mock_aioresponse, auth_client, fake_email, fake_token
):
    mock_aioresponse.post(
        f"{auth_client.host}/token/verify/{auth_client.app_id}",
        status=200,
        payload={"headers": {"one": "hi"}, "claims": {"sub": fake_email}},
    )

    result = await auth_client.verify_token_remote(fake_token)

    assert "headers" in result
    assert "claims" in result

    request_args = list(mock_aioresponse.requests.values())[0][0].kwargs
    assert request_args["json"]["idToken"] == fake_token


@pytest.mark.asyncio
async def test_verify_token_remote_failure(mock_aioresponse, auth_client, fake_token):
    mock_aioresponse.post(
        f"{auth_client.host}/token/verify/{auth_client.app_id}",
        status=401,
    )

    with pytest.raises(AuthenticationFailure):
        await auth_client.verify_token_remote(fake_token)


@pytest.mark.asyncio
async def test_verify_token_no_response_from_server(
    mock_aioresponse, auth_client, fake_token
):
    mock_aioresponse.post(
        f"{auth_client.host}/token/verify/{auth_client.app_id}",
        status=200,
    )

    with pytest.raises(AuthenticationFailure):
        await auth_client.verify_token_remote(fake_token)


@pytest.mark.asyncio
async def test_verify_token_invalid_response_from_server(
    mock_aioresponse, auth_client, fake_token
):
    mock_aioresponse.post(
        f"{auth_client.host}/token/verify/{auth_client.app_id}",
        status=200,
        payload={"random": "nonsense"},
    )

    with pytest.raises(AuthenticationFailure):
        await auth_client.verify_token_remote(fake_token)


@pytest.mark.asyncio
async def test_verify_token_not_found(mock_aioresponse, auth_client, fake_token):
    mock_aioresponse.post(
        f"{auth_client.host}/token/verify/{auth_client.app_id}",
        status=404,
    )

    with pytest.raises(AppNotFound):
        await auth_client.verify_token_remote(fake_token)


@pytest.mark.asyncio
async def test_verify_remote_validation_error(
    mock_aioresponse, auth_client, fake_token
):
    mock_aioresponse.post(
        f"{auth_client.host}/token/verify/{auth_client.app_id}",
        status=422,
    )

    with pytest.raises(ValidationError):
        await auth_client.verify_token_remote(fake_token)


@pytest.mark.asyncio
async def test_verify_remote_server_error(mock_aioresponse, auth_client, fake_token):
    mock_aioresponse.post(
        f"{auth_client.host}/token/verify/{auth_client.app_id}",
        status=500,
    )

    with pytest.raises(ServerError):
        await auth_client.verify_token_remote(fake_token)


@pytest.mark.asyncio
async def test_refresh_token(
    mock_aioresponse, auth_client, fake_token, fake_refresh_token
):
    mock_aioresponse.post(
        f"{auth_client.host}/token/refresh/{auth_client.app_id}",
        status=200,
        payload={"idToken": fake_token, "refreshToken": fake_refresh_token},
    )

    result = await auth_client.refresh(fake_refresh_token)

    assert result == fake_token

    request_args = list(mock_aioresponse.requests.values())[0][0].kwargs
    assert request_args["json"]["refreshToken"] == fake_refresh_token


@pytest.mark.asyncio
async def test_refresh_token_failure(mock_aioresponse, auth_client, fake_refresh_token):
    mock_aioresponse.post(
        f"{auth_client.host}/token/refresh/{auth_client.app_id}",
        status=401,
    )

    with pytest.raises(AuthenticationFailure):
        await auth_client.refresh(fake_refresh_token)


@pytest.mark.asyncio
async def test_refresh_token_no_response_from_server(
    mock_aioresponse, auth_client, fake_refresh_token
):
    mock_aioresponse.post(
        f"{auth_client.host}/token/refresh/{auth_client.app_id}",
        status=200,
    )

    with pytest.raises(AuthenticationFailure):
        await auth_client.refresh(fake_refresh_token)


@pytest.mark.asyncio
async def test_refresh_token_invalid_response_from_server(
    mock_aioresponse, auth_client, fake_refresh_token
):
    mock_aioresponse.post(
        f"{auth_client.host}/token/refresh/{auth_client.app_id}",
        status=200,
        payload={"random": "nonsense"},
    )

    with pytest.raises(AuthenticationFailure):
        await auth_client.refresh(fake_refresh_token)


@pytest.mark.asyncio
async def test_refresh_token_not_found(
    mock_aioresponse, auth_client, fake_refresh_token
):
    mock_aioresponse.post(
        f"{auth_client.host}/token/refresh/{auth_client.app_id}",
        status=404,
    )

    with pytest.raises(AppNotFound):
        await auth_client.refresh(fake_refresh_token)


@pytest.mark.asyncio
async def test_refresh_token_validation_error(
    mock_aioresponse, auth_client, fake_refresh_token
):
    mock_aioresponse.post(
        f"{auth_client.host}/token/refresh/{auth_client.app_id}",
        status=422,
    )

    with pytest.raises(ValidationError):
        await auth_client.refresh(fake_refresh_token)


@pytest.mark.asyncio
async def test_refresh_token_server_error(
    mock_aioresponse, auth_client, fake_refresh_token
):
    mock_aioresponse.post(
        f"{auth_client.host}/token/refresh/{auth_client.app_id}",
        status=500,
    )

    with pytest.raises(ServerError):
        await auth_client.refresh(fake_refresh_token)


@pytest.mark.asyncio
async def test_app_info(mock_aioresponse, auth_client, fake_name):
    mock_aioresponse.get(
        f"{auth_client.host}/app/{auth_client.app_id}",
        status=200,
        payload={
            "name": fake_name,
            "app_id": auth_client.app_id,
            "redirect_url": "https://redirect.example.com",
        },
    )

    result = await auth_client.app_info()

    assert result["name"] == fake_name
    assert result["app_id"] == auth_client.app_id
    assert result["redirect_url"] == "https://redirect.example.com"


@pytest.mark.asyncio
async def test_app_info_not_found(mock_aioresponse, auth_client):
    mock_aioresponse.get(
        f"{auth_client.host}/app/{auth_client.app_id}",
        status=404,
    )

    with pytest.raises(AppNotFound):
        await auth_client.app_info()


@pytest.mark.asyncio
async def test_app_info_server_error(mock_aioresponse, auth_client):
    mock_aioresponse.get(
        f"{auth_client.host}/app/{auth_client.app_id}",
        status=500,
    )

    with pytest.raises(ServerError):
        await auth_client.app_info()


@pytest.mark.asyncio
async def test_verify_token_success(auth_client, fake_key, valid_token, fake_email):
    result = await auth_client.verify(valid_token)

    assert result["claims"]["sub"] == fake_email


@pytest.mark.asyncio
async def test_verify_token_failure(auth_client, fake_key, invalid_token):
    with pytest.raises(AuthenticationFailure):
        await auth_client.verify(invalid_token)


@pytest.mark.asyncio
async def test_verify_token_expired(auth_client, fake_key, expired_token):
    with pytest.raises(AuthenticationFailure):
        await auth_client.verify(expired_token)


@pytest.mark.asyncio
async def test_delete_refresh_token(
    mock_aioresponse, auth_client, fake_refresh_token, fake_token
):
    mock_aioresponse.delete(
        f"{auth_client.host}/token/refresh/{auth_client.app_id}/{fake_refresh_token}",
        status=204,
    )

    await auth_client.delete_refresh_token(fake_token, fake_refresh_token)

    request_args = list(mock_aioresponse.requests.values())[0][0].kwargs
    print(request_args)
    assert request_args["headers"]["Authorization"] == f"Bearer {fake_token}"


@pytest.mark.asyncio
async def test_delete_refresh_token_unauthorized(
    mock_aioresponse, auth_client, fake_refresh_token, fake_token
):
    mock_aioresponse.delete(
        f"{auth_client.host}/token/refresh/{auth_client.app_id}/{fake_refresh_token}",
        status=401,
    )

    with pytest.raises(AuthenticationFailure):
        await auth_client.delete_refresh_token(fake_token, fake_refresh_token)


@pytest.mark.asyncio
async def test_delete_refresh_token_not_found(
    mock_aioresponse, auth_client, fake_refresh_token, fake_token
):
    mock_aioresponse.delete(
        f"{auth_client.host}/token/refresh/{auth_client.app_id}/{fake_refresh_token}",
        status=404,
    )

    with pytest.raises(AppNotFound):
        await auth_client.delete_refresh_token(fake_token, fake_refresh_token)


@pytest.mark.asyncio
async def test_delete_refresh_token_server_error(
    mock_aioresponse, auth_client, fake_refresh_token, fake_token
):
    mock_aioresponse.delete(
        f"{auth_client.host}/token/refresh/{auth_client.app_id}/{fake_refresh_token}",
        status=500,
    )

    with pytest.raises(ServerError):
        await auth_client.delete_refresh_token(fake_token, fake_refresh_token)


@pytest.mark.asyncio
async def test_delete_all_refresh_tokens(mock_aioresponse, auth_client, fake_token):
    mock_aioresponse.delete(
        f"{auth_client.host}/token/refresh/{auth_client.app_id}",
        status=204,
    )

    await auth_client.delete_all_refresh_tokens(fake_token)

    request_args = list(mock_aioresponse.requests.values())[0][0].kwargs
    print(request_args)
    assert request_args["headers"]["Authorization"] == f"Bearer {fake_token}"


@pytest.mark.asyncio
async def test_delete_all_refresh_tokens_not_found(
    mock_aioresponse, auth_client, fake_token
):
    mock_aioresponse.delete(
        f"{auth_client.host}/token/refresh/{auth_client.app_id}",
        status=404,
    )

    with pytest.raises(AppNotFound):
        await auth_client.delete_all_refresh_tokens(fake_token)


@pytest.mark.asyncio
async def test_delete_all_refresh_tokens_server_error(
    mock_aioresponse, auth_client, fake_token
):
    mock_aioresponse.delete(
        f"{auth_client.host}/token/refresh/{auth_client.app_id}",
        status=500,
    )

    with pytest.raises(ServerError):
        await auth_client.delete_all_refresh_tokens(fake_token)


@pytest.mark.asyncio
async def test_delete_all_refresh_tokens_unauthorized(
    mock_aioresponse, auth_client, fake_token
):
    mock_aioresponse.delete(
        f"{auth_client.host}/token/refresh/{auth_client.app_id}",
        status=401,
    )

    with pytest.raises(AuthenticationFailure):
        await auth_client.delete_all_refresh_tokens(fake_token)


@pytest.mark.asyncio
async def test_no_id_token_raises_value_error(auth_client):
    with pytest.raises(ValueError):
        await auth_client.verify(None)


@pytest.mark.asyncio
async def test_no_refresh_token_raises_value_error(auth_client):
    with pytest.raises(ValueError):
        await auth_client.refresh(None)
