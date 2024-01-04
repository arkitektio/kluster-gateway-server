from dask_gateway_server.auth import SimpleAuthenticator, unauthorized, User, base64
import logging
import jwt
import os
from omegaconf import OmegaConf
from pydantic import BaseModel, Field
import re
from typing import Type, List
import dataclasses


conf = OmegaConf.load(os.path.join(os.getcwd(), "config.yaml"))

logger = logging.getLogger(__name__)

__all__ = ["JWTAuthenticator"]

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



class AuthSettings(BaseModel):
    public_key: str
    issuer: str = "lok"
    key_type: str = "RS256"
    authorization_headers: list[str] = Field(
        default_factory=lambda: [
            "Authorization",
            "X-Authorization",
            "AUTHORIZATION",
            "authorization",
        ]
    )


def get_auth_settings() -> AuthSettings:
    return AuthSettings(
        public_key=conf.lok.public_key, 
        issuer=conf.lok.issuer,
        key_type=conf.lok.key_type,
    )

class JWTToken(BaseModel):
    """A JWT token

    This is a pydantic model that represents a JWT token.
    It is used to validate the token and to extract information from it.
    The token is decoded using the `decode_token` function.

    """

    sub: str
    """A unique identifier for the user (is unique for the issuer)"""
    iss: str
    """The issuer of the token"""
    exp: int
    """The expiration time of the token"""
    client_id: str
    """The client_id of the app that requested the token"""
    preferred_username: str
    """The username of the user"""
    roles: list[str]
    """The roles of the user"""
    scope: str
    """The scopes of the token"""

    aud: str | None = None
    """The audience of the token"""

    @property
    def changed_hash(self) -> str:
        """A hash that changes when the user changes"""
        return str(hash(self.sub + self.preferred_username + " ".join(self.roles)))

    @property
    def scopes(self) -> list[str]:
        """The scopes of the token. Each scope is a string separated by a space"""
        return self.scope.split(" ")

    class Config:
        """Pydantic config"""

        extra = "ignore"



@dataclasses.dataclass
class Auth:
    """
    Mimics the structure of `AbstractAccessToken` so you can use standard
    Django Oauth Toolkit permissions like `TokenHasScope`.
    """

    token: JWTToken
    user: User

    def has_scopes(self, scopes: List[str]) -> bool:
        """Does the token have the required scopes?

        Check if the token has the required scopes, if no scopes are provided
        it will return True.

        Parameters
        ----------
        scopes : list[str]
            The scopes to check

        Returns
        -------
        bool
            Does the token have the required scopes?
        """

        provided_scopes = set(self.token.scopes)
        resource_scopes = set(scopes)

        return resource_scopes.issubset(provided_scopes)



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

    decoded = jwt.decode(token, settings.public_key, algorithms=[settings.key_type])

    token = JWTToken(**decoded)


    user = User(name=f"{token.iss}_{token.sub}", groups=token.roles)
    return Auth(token=token, user=user)




class JWTAuthenticator(SimpleAuthenticator):
     password: str = "supersecret"


    
     async def authenticate(self, request):
        
        try:
            headers = request.headers
            print(request.headers)
            auth = authenticate_header(headers, get_auth_settings())
        except Exception as e:
            print(e)
            logger.error("Authenticating failed", exc_info=True)
            raise unauthorized("Basic")

        return auth.user







c.LocalBackend.default_host = "0.0.0.0"
c.DaskGateway.address = "0.0.0.0:0"
c.DaskGateway.authenticator_class = JWTAuthenticator


