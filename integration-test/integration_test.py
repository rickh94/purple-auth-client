import json
import os
import re
import subprocess
from pathlib import Path

import pytest
import requests

from ricks_auth_service_client import AuthClient


@pytest.fixture
def auth_client():
    return AuthClient("http://localhost:25898", "123456")


@pytest.mark.asyncio
async def test_code_flow(auth_client):
    wd = os.getcwd()
    here = Path(__file__).parent
    os.chdir(here)
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
    os.chdir(wd)


@pytest.mark.asyncio
async def test_magic_flow(auth_client):
    wd = os.getcwd()
    here = Path(__file__).parent
    os.chdir(here)
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
    os.chdir(wd)
