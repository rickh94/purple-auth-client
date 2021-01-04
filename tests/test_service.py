from ricks_auth_service_client import AuthClient


def test_exists():
    client = AuthClient("localhost")
    assert client.host == "localhost"
