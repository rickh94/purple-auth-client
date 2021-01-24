# ricks_auth_service_client

An async python client for my custom auth microservice.

## Routes Covered

### initialization

```python
from ricks_auth_service_client import AuthClient

auth_client = AuthClient(
    host="https://auth.example.com",
    app_id="37f9a26d-03c8-4b7c-86ad-132bb82e8e38"
)
```

### /otp/request/

Start otp authentication flow with server.

```python
result = await auth_client.authenticate(
    "test@example.com", flow="otp"
)
```

### /otp/confirm/

Complete authentication with email and generated code.

```python
result = await auth_client.submit_code("test@example.com", "12345678")
```

### /token/verify/

Send idToken to server for verification.

```python
result = await auth_client.verify_token_remote(token_submitted_by_client)
```

### /token/refresh/

Request a new ID Token from the server using a refresh token

```python
new_token = await auth_client.refresh(refresh_token_from_client)
```


### /app/

Get more info about this app from the server.

```python
info = await auth_client.app_info()
```


### /magic/request/

Start authentication using magic link flow.

```python
result = await auth_client.authenticate(
    "test@example.com", flow="magic"
)
```


## Local Verification


