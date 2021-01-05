import pytest
from aioresponses import aioresponses

from ricks_auth_service_client import (
    AuthClient,
    AppNotFound,
    ServerError,
    ValidationError,
    AuthenticationFailure,
    AuthClientError,
)


@pytest.fixture
def auth_client():
    return AuthClient("auth.example.com", "123456")


@pytest.fixture
def mock_aioresponse():
    with aioresponses() as m:
        yield m


def test_create():
    client = AuthClient("localhost", "12345")
    assert client.host == "https://localhost"
    assert client.app_id == "12345"
    assert client._public_key is None


@pytest.mark.asyncio
async def test_authenticate_success(mock_aioresponse, auth_client, faker):
    fake_email = faker.email()
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
async def test_authenticate_not_found(mock_aioresponse, auth_client, faker):
    fake_email = faker.email()
    mock_aioresponse.post(
        f"{auth_client.host}/otp/request/{auth_client.app_id}",
        status=404,
    )
    with pytest.raises(AppNotFound):
        await auth_client.authenticate(fake_email)


@pytest.mark.asyncio
async def test_authenticate_server_error(mock_aioresponse, auth_client, faker):
    fake_email = faker.email()
    mock_aioresponse.post(
        f"{auth_client.host}/otp/request/{auth_client.app_id}",
        status=500,
    )
    with pytest.raises(ServerError):
        await auth_client.authenticate(fake_email)


@pytest.mark.asyncio
async def test_authenticate_validation_error(mock_aioresponse, auth_client, faker):
    fake_email = faker.email()
    mock_aioresponse.post(
        f"{auth_client.host}/otp/request/{auth_client.app_id}",
        status=422,
    )
    with pytest.raises(ValidationError):
        await auth_client.authenticate(fake_email)


@pytest.mark.asyncio
async def test_submit_code_success(mock_aioresponse, auth_client, faker):
    fake_email = faker.email()
    test_code = "11111111"
    mock_aioresponse.post(
        f"{auth_client.host}/otp/confirm/{auth_client.app_id}",
        status=200,
        payload={"idToken": "fake-id-token"},
    )

    output = await auth_client.submit_code(fake_email, test_code)

    assert output == {"id_token": "fake-id-token"}

    request_args = list(mock_aioresponse.requests.values())[0][0].kwargs
    assert request_args["json"]["email"] == fake_email
    assert request_args["json"]["code"] == test_code


@pytest.mark.asyncio
async def test_submit_code_not_found(mock_aioresponse, auth_client, faker):
    fake_email = faker.email()
    test_code = "11111111"
    mock_aioresponse.post(
        f"{auth_client.host}/otp/confirm/{auth_client.app_id}",
        status=404,
    )

    with pytest.raises(AppNotFound):
        await auth_client.submit_code(fake_email, test_code)


@pytest.mark.asyncio
async def test_submit_code_validation_error(mock_aioresponse, auth_client, faker):
    fake_email = faker.email()
    test_code = "11111111"
    mock_aioresponse.post(
        f"{auth_client.host}/otp/confirm/{auth_client.app_id}",
        status=422,
    )

    with pytest.raises(ValidationError):
        await auth_client.submit_code(fake_email, test_code)


@pytest.mark.asyncio
async def test_submit_code_server_error(mock_aioresponse, auth_client, faker):
    fake_email = faker.email()
    test_code = "11111111"
    mock_aioresponse.post(
        f"{auth_client.host}/otp/confirm/{auth_client.app_id}",
        status=500,
    )

    with pytest.raises(ServerError):
        await auth_client.submit_code(fake_email, test_code)


@pytest.mark.asyncio
async def test_submit_code_authentication_failed(mock_aioresponse, auth_client, faker):
    fake_email = faker.email()
    test_code = "11111111"
    mock_aioresponse.post(
        f"{auth_client.host}/otp/confirm/{auth_client.app_id}",
        status=401,
    )

    with pytest.raises(AuthenticationFailure):
        await auth_client.submit_code(fake_email, test_code)


@pytest.mark.asyncio
async def test_submit_code_missing_response_from_server(
    mock_aioresponse, auth_client, faker
):
    fake_email = faker.email()
    test_code = "11111111"
    mock_aioresponse.post(
        f"{auth_client.host}/otp/confirm/{auth_client.app_id}",
        status=200,
    )

    with pytest.raises(AuthClientError):
        await auth_client.submit_code(fake_email, test_code)


@pytest.mark.asyncio
async def test_submit_code_missing_token_in_response(
    mock_aioresponse, auth_client, faker
):
    fake_email = faker.email()
    test_code = "11111111"
    mock_aioresponse.post(
        f"{auth_client.host}/otp/confirm/{auth_client.app_id}",
        status=200,
        payload={"nothing": "useful"},
    )

    with pytest.raises(AuthClientError):
        await auth_client.submit_code(fake_email, test_code)
