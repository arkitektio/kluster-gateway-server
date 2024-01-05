from pydantic import BaseModel, Field
import datetime
import dataclasses
from dask_gateway_server.auth import User



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

class StaticToken(JWTToken):
    """A static JWT token"""

    sub: str
    iss: str = "static"
    exp: int = Field(
        default_factory=lambda: int(
            (datetime.datetime.utcnow() + datetime.timedelta(days=1)).timestamp()
        )
    )
    client_id: str = "static"
    preferred_username: str = "static_user"
    scope: str = "openid profile email"
    roles: list[str] = Field(default_factory=lambda: ["static"])


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
    static_tokens: dict[str, StaticToken] = Field(default_factory=dict)


@dataclasses.dataclass
class Auth:
    """
    Mimics the structure of `AbstractAccessToken` so you can use standard
    Django Oauth Toolkit permissions like `TokenHasScope`.
    """

    token: JWTToken
    user: User

    def has_scopes(self, scopes: list[str]) -> bool:
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


AuthSettings.update_forward_refs()