import functools
import json
import os
import re
import subprocess
from pathlib import Path

import pytest
import requests
from jwcrypto import jwk
import python_jwt as jwt

from purple_auth_client import AuthClient, AuthenticationFailure


@pytest.fixture
def auth_client():
    return AuthClient("http://localhost:25898", "123456")


@pytest.fixture
def auth_client2():
    return AuthClient("http://localhost:25898", "2")


def correct_dir(func):
    here = Path(__file__).parent

    @functools.wraps(func)
    async def _wrapper(*args, **kwargs):
        wd = os.getcwd()
        os.chdir(here)
        await func(*args, **kwargs)
        os.chdir(wd)

    return _wrapper


@pytest.mark.asyncio
@correct_dir
async def test_code_flow(auth_client):
    response = await auth_client.authenticate("test@example.com")
    assert response == "Check your email for a login code"
    output = subprocess.run(
        [
            "docker-compose",
            "run",
            "--rm",
            "volume-access",
            "sh",
            "-c",
            "cat /test-data/email-to-test@example.com.json",
        ],
        stdout=subprocess.PIPE,
    )

    data = json.loads(output.stdout)

    assert data["to"] == "test@example.com"
    assert data["from"] == "App <test@mg.example.com>"
    assert data["subject"] == "Your One Time Login Code"
    assert "Your code is" in data["text"]
    assert "It will expire in " in data["text"]
    assert "minutes." in data["text"]

    found = re.search(r"Your code is ([0-9]*)", data["text"])
    code = found.group(1)

    result = await auth_client.submit_code("test@example.com", code)

    assert "id_token" in result
    assert "refresh_token" in result

    remote_verification_result = await auth_client.verify_token_remote(
        result["id_token"]
    )

    assert "headers" in remote_verification_result
    assert "claims" in remote_verification_result

    assert remote_verification_result["claims"]["sub"] == "test@example.com"

    local_verification_result = await auth_client.verify(result["id_token"])

    assert "headers" in local_verification_result
    assert "claims" in local_verification_result

    assert local_verification_result["claims"]["sub"] == "test@example.com"

    new_id_token = await auth_client.refresh(result["refresh_token"])

    assert new_id_token is not None

    await auth_client.verify(new_id_token)


@pytest.mark.asyncio
@correct_dir
async def test_magic_flow(auth_client):
    response = await auth_client.authenticate("test2@example.com", "magic")
    assert response == "Check your email for a login link."
    output = subprocess.run(
        [
            "docker-compose",
            "run",
            "--rm",
            "volume-access",
            "sh",
            "-c",
            "cat /test-data/email-to-test2@example.com.json",
        ],
        stdout=subprocess.PIPE,
    )

    data = json.loads(output.stdout)

    assert data["to"] == "test2@example.com"
    assert data["from"] == "App <test@mg.example.com>"
    assert data["subject"] == "Your Magic Sign In Link"
    assert "Click or copy this link to sign in:" in data["text"]
    assert "It will expire in " in data["text"]
    assert "minutes." in data["text"]

    found = re.search(r"Click or copy this link to sign in: (.*)\. ", data["text"])
    link = found.group(1)
    response = requests.get(link)

    assert response.status_code == 200

    token_output = subprocess.run(
        [
            "docker-compose",
            "run",
            "--rm",
            "volume-access",
            "sh",
            "-c",
            "cat /test-data/magic-from-test2@example.com.json",
        ],
        stdout=subprocess.PIPE,
    )

    token_data = json.loads(token_output.stdout)
    assert "idToken" in token_data
    assert "refreshToken" in token_data

    remote_verification_result = await auth_client.verify_token_remote(
        token_data["idToken"]
    )

    assert "headers" in remote_verification_result
    assert "claims" in remote_verification_result

    assert remote_verification_result["claims"]["sub"] == "test2@example.com"

    local_verification_result = await auth_client.verify(token_data["idToken"])

    assert "headers" in local_verification_result
    assert "claims" in local_verification_result

    assert local_verification_result["claims"]["sub"] == "test2@example.com"

    new_id_token = await auth_client.refresh(token_data["refreshToken"])

    assert new_id_token is not None

    await auth_client.verify(new_id_token)


@pytest.mark.asyncio
@correct_dir
async def test_code_flow_wrong_code(auth_client):
    response = await auth_client.authenticate("test@example.com")
    assert response == "Check your email for a login code"
    with pytest.raises(AuthenticationFailure):
        await auth_client.submit_code("test@example.com", "111111111")


@pytest.mark.asyncio
@correct_dir
async def test_remote_verify_invalid_token_fails(auth_client):
    key = jwk.JWK.generate(kty="EC", size=2048)
    token = jwt.generate_jwt({"sub": "test3@example.com"}, key, "ES256")
    with pytest.raises(AuthenticationFailure):
        await auth_client.verify_token_remote(token)


@pytest.mark.asyncio
@correct_dir
async def test_local_verify_invalid_token_fails(auth_client):
    key = jwk.JWK.generate(kty="EC", size=2048)
    token = jwt.generate_jwt({"sub": "test3@example.com"}, key, "ES256")
    with pytest.raises(AuthenticationFailure):
        await auth_client.verify(token)


async def perform_code_auth(auth_client, email):
    await auth_client.authenticate(email)
    output = subprocess.run(
        [
            "docker-compose",
            "run",
            "--rm",
            "volume-access",
            "sh",
            "-c",
            f"cat /test-data/email-to-{email}.json",
        ],
        stdout=subprocess.PIPE,
    )

    data = json.loads(output.stdout)
    found = re.search(r"Your code is ([0-9]*)", data["text"])
    code = found.group(1)

    return await auth_client.submit_code(email, code)


@pytest.mark.asyncio
@correct_dir
async def test_verify_from_other_app_fails(auth_client, auth_client2):
    result = await perform_code_auth(auth_client, "test4@example.com")

    with pytest.raises(AuthenticationFailure):
        await auth_client2.verify_token_remote(result["id_token"])

    with pytest.raises(AuthenticationFailure):
        await auth_client2.verify(result["id_token"])


@pytest.mark.asyncio
@correct_dir
async def test_delete_refresh_token(auth_client):
    result = await perform_code_auth(auth_client, "test9@example.com")

    await auth_client.delete_refresh_token(result["id_token"], result["refresh_token"])

    with pytest.raises(AuthenticationFailure):
        await auth_client.refresh(result["refresh_token"])


@pytest.mark.asyncio
@correct_dir
async def test_delete_all_refresh_tokens(auth_client):
    result1 = await perform_code_auth(auth_client, "test5@example.com")
    result2 = await perform_code_auth(auth_client, "test5@example.com")

    await auth_client.delete_all_refresh_tokens(result1["id_token"])

    with pytest.raises(AuthenticationFailure):
        await auth_client.refresh(result1["refresh_token"])

    with pytest.raises(AuthenticationFailure):
        await auth_client.refresh(result2["refresh_token"])
