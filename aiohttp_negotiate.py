import base64
import logging
from urllib.parse import urlparse

import aiohttp
import gssapi
import www_authenticate

logger = logging.getLogger(__name__)

# Different types of mutual authentication:
#  with mutual_authentication set to REQUIRED, all responses will be
#   authenticated with the exception of errors. Errors will have their contents
#   and headers stripped. If a non-error response cannot be authenticated, a
#   MutualAuthenticationError exception will be raised.
#   In the case of a response being redirected, it will act as OPTIONAL.
# with mutual_authentication set to OPTIONAL, mutual authentication will be
#   attempted if supported, and if supported and failed, a
#   MutualAuthenticationError exception will be raised. Responses which do not
#   support mutual authentication will be returned directly to the user.
# with mutual_authentication set to DISABLED, mutual authentication will not be
#   attempted, even if supported.
REQUIRED = 1
OPTIONAL = 2
DISABLED = 3


class MutualAuthenticationError(aiohttp.exception.TraceRequestExceptionParams):
    """Mutual Authentication Error"""


class NegotiateMixin(object):
    def __init__(self, *,
                 negotiate_client_name=None,
                 negotiate_service_name=None,
                 negotiate_service='HTTP',
                 mutual_authentication=REQUIRED,
                 **kwargs):
        self.negotiate_client_name = negotiate_client_name
        self.negotiate_service_name = negotiate_service_name
        self.negotiate_service = negotiate_service
        self.mutual_authentication = mutual_authentication
        super().__init__(**kwargs)


    def get_context(self, host):
        service_name = gssapi.Name(self.negotiate_service_name or '{0}@{1}'.format(self.negotiate_service, host),
                                   gssapi.NameType.hostbased_service)
        logger.debug("Service name: {0}".format(service_name))
        if self.negotiate_client_name:
            creds = gssapi.Credentials(name=gssapi.Name(self.negotiate_client_name),
                                       usage='initiate')
        else:
            creds = None
        logger.debug("Credentials: {0}".format(creds))
        return gssapi.SecurityContext(name=service_name,
                                      creds=creds)

    def negotiate_step(self, ctx, in_token=None):
        if in_token:
            in_token = base64.b64decode(in_token)
        out_token = ctx.step(in_token)
        if out_token:
            out_token = base64.b64encode(out_token).decode('utf-8')
        return out_token

    async def _request(self, method, url, *, headers=None, **kwargs):
        headers = headers or {}
        host = urlparse(url).hostname
        while True:
            ctx = self.get_context(host)
            out_token = self.negotiate_step(ctx)
            if out_token:
                headers['Authorization'] = 'Negotiate ' + out_token
            response = await super()._request(method, url, headers=headers, **kwargs)
            host = response.url.host
            challenges = www_authenticate.parse(response)

            # The following lines have been adapted in order to be compatible with
            # a request being transparently redirected, in some cases the next host
            # will not send a negotiate parameter, so the server cannot be authenticated.
            # To avoid the exception, that kind of request is being treated as OPTIONAL
            # authentication.
            # TODO: manage the request to allow Mutual authentication when
            #  the requests is being redirected.
            if self.mutual_authentication == DISABLED:
                break
            in_token = challenges.get('negotiate', False)
            if not in_token:
                if kwargs["allow_redirects"] or self.mutual_authentication == OPTIONAL:
                    break
                raise MutualAuthenticationError("Unable to authenticate "
                                                "{0}".format(response))
            self.negotiate_step(ctx, in_token)
            if ctx.complete:
                break
            response.close()
        return response

class NegotiateClientSession(NegotiateMixin, aiohttp.ClientSession):
    pass

