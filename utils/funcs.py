from .models import Auth, JWTToken, User, AuthSettings
import jwt
import re

jwt_re = re.compile(r"Bearer\s(?P<token>[^\s]*)")


def extract_plain_from_authorization(authorization: str) -> str:
    """
    Extract a plain token from an Authorization header

    Parameters
    ----------

    authorization : str
        The Authorization header

    Returns
    -------
    str
        The token
    """
    m = jwt_re.match(authorization)
    if m:
        token = m.group("token")
        return token

    raise ValueError("Not a valid token")


def authenticate_header(
    headers: dict[str, str], settings: AuthSettings | None = None
) -> Auth:
    """
    Authenticate a request and return the auth context
    (containing user, app and scopes)

    """
    for i in settings.authorization_headers:
        print("Checking", i)
        authorization = headers.get(i, None)
        if authorization:
            break

    if not authorization:
        raise ValueError("No Authorization header")

    token = extract_plain_from_authorization(authorization)

    if token in settings.static_tokens:
        jwttoken = settings.static_tokens[token]
    else:
        decoded = jwt.decode(token, settings.public_key, algorithms=[settings.key_type])
        jwttoken = JWTToken(**decoded)


    user = User(name=f"{jwttoken.iss}_{jwttoken.sub}", groups=jwttoken.roles)
    return Auth(token=jwttoken, user=user)



