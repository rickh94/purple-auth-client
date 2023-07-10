# Purple Auth Client (Python)

An async python client for my ["Purple Auth"
microservice](https://purpleauth.com).


### Initialization

Create an account and application on [purpelauth.com](https://purpleauth.com),
then initialize the client with those values. You should store the api key in an
environment variable, but the app id is a public value, not a secret.

```python
from purple_auth_client import AuthClient

auth_client = AuthClient(
    host="https://purpleauth.com",
    app_id="37f9a26d-03c8-4b7c-86ad-132bb82e8e38",
    api_key="[Key provided by purple auth portal]"
)
```
 
You will initially be limited to 500 authentications per app, but you can email
me to have that increased.

## Routes Covered

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

You should prefer to verify tokens locally using the `verify` method, but this
is covered as a convenience and sanity check.

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

Verify and decode an ID Token on directly in the app without having to
call out every time

```python
result = await auth_client.verify(id_token_from_client)
# {"headers": {"alg": "ES256", "type": "JWT"}, "claims": {"sub": "user@email.com", "exp": "test@example.com"}
# etc.

```

