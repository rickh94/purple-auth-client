import pytest
from aioresponses import aioresponses
from faker import Faker

from ricks_auth_service_client import (
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
    return AuthClient("auth.example.com", "123456")


@pytest.fixture
def mock_aioresponse():
    with aioresponses() as m:
        yield m


@pytest.fixture
def fake_email():
    return Faker().email()


@pytest.fixture
def test_code():
    return "11111111"


@pytest.fixture
def fake_token():
    return "this-is-a-fake-jwt"


def test_create():
    client = AuthClient("localhost", "12345")
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
