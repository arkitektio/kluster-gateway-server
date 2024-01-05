import sys
import os
sys.path.append(os.getcwd()) # add current working directory to path
# otherwise the import below will fail



from dask_gateway_server.auth import SimpleAuthenticator, unauthorized, User, base64
import logging
import os
from omegaconf import OmegaConf


from utils.models import AuthSettings
from utils.funcs import authenticate_header

conf = OmegaConf.load(os.path.join(os.getcwd(), "config.yaml"))

logger = logging.getLogger(__name__)

__all__ = ["JWTAuthenticator"]



def get_auth_settings() -> AuthSettings:
    return AuthSettings(
        public_key=conf.lok.public_key, 
        issuer=conf.lok.issuer,
        key_type=conf.lok.key_type,
        static_tokens=conf.lok.get("static_tokens", {})
    )


class JWTAuthenticator(SimpleAuthenticator):


    
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


