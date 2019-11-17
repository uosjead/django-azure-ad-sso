from django.conf import settings

from django.contrib.auth.models import User

import os
import requests
import uuid
from django.shortcuts import render, redirect
from django.core.exceptions import PermissionDenied
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie
from django.views.decorators.cache import never_cache
from django.contrib.auth.backends import ModelBackend
from django.utils.functional import cached_property
from django.http import HttpResponseForbidden, HttpResponseRedirect
from django.core.signing import TimestampSigner
from django.core import signing
import jwt
from django.contrib.sessions.backends.db import SessionStore

import hmac
import hashlib
import base64

try:
    from urllib.parse import urlparse, urlencode, quote_plus  # , urlsplit
except ImportError:
    from urlparse import urlparse  # , urlsplit
    from urllib import urlencode, quote_plus

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from django.contrib.auth import login, logout
from django.contrib.sessions.models import Session

try:
    from django.contrib.auth import get_user_model
except ImportError:
    from django.contrib.auth.models import User


    def get_user_model(*args, **kwargs):
        return User


class AzureADAuthFailed(PermissionDenied):
    pass

'''

this module does not support login over HTTP, HTTPS only must be set (see setings below)

#add to settings.py

    AUTHENTICATION_BACKENDS = (
     'azure_ad_sso.backends.AzureADBackend',
     'django.contrib.auth.backends.ModelBackend',
    )

    MIDDLEWARE = (
        'django.contrib.sessions.middleware.SessionMiddleware', 
    )

    #the email is used as the Django Username

    AZURE_AD_SSO_TENANT_ID = 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX'
    #
    AZURE_AD_SSO_CLIENT_ID = 'YYYYYYYY-YYYY-YYYY-YYYY-YYYYYYYYYYYY'

    AZURE_AD_SSO_LOGIN_URL = "/login"

    LOGIN_REDIRECT_URL = '/aad_authcomplete'

    AZURE_AD_SSO_HOST = 'login.microsoftonline.com'

    CSRF_TRUSTED_ORIGINS = [AZURE_AD_SSO_HOST]

    SECURE_COOKIE_DOMAIN = AZURE_AD_SSO_HOST

    ###optionally
    AZURE_AD_SSO_POST_LOGOUT_URL = '/where_to_go_after_logout'

    #add this middleware to requied login for all views
    MIDDLEWARE = (
     ...
     "azure_ad_sso.middleware.SSORequireLoginMiddleware",
    )

    ##these below are required to force https
    SECURE_SSL_REDIRECT = True
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

    #add these for good measure if you haven't already
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_HSTS_SECONDS = 10
    SECURE_HSTS_PRELOAD = True


#add to urls.py

    from django.conf.urls import url
    from ...backends import AzureADBackend

    ...
    urlpatterns = [
        #...
            url(r'^login/$', AzureADBackend.ad_login),
            url(r'^auth_complete/', AzureADBackend.ad_authcomplete),

        #...
    ]

    /authorize
    tenant	REQUIRED	The {tenant} value in the path of the request can be used to control who can sign into the application. The allowed values are tenant identifiers, for example, 8eaef023-2b34-4da1-9baa-8bc8c9d6a490 or contoso.onmicrosoft.com or common for tenant-independent tokens
    client_id	REQUIRED	The Application ID assigned to your app when you registered it with Azure AD. You can find this in the Azure Portal. Click Azure Active Directory in the services sidebar, click App registrations, and choose the application.
    response_type	REQUIRED	Must include code for the authorization code flow.
    redirect_uri	RECOMMENDED	The redirect_uri of your app, where authentication responses can be sent and received by your app. It must exactly match one of the redirect_uris you registered in the portal, except it must be url encoded. For native & mobile apps, you should use the default value of urn:ietf:wg:oauth:2.0:oob.
    response_mode	OPTIONAL	Specifies the method that should be used to send the resulting token back to your app. Can be query, fragment, or form_post. query provides the code as a query string parameter on your redirect URI. If you're requesting an ID token using the implicit flow, you cannot use query as specified in the OpenID spec. If you're requesting just the code, you can use query, fragment, or form_post. form_post executes a POST containing the code to your redirect URI. The default is query for a code flow.
    state	RECOMMENDED	A value included in the request that is also returned in the token response. A randomly generated unique value is typically used for preventing cross-site request forgery attacks. The state is also used to encode information about the user's state in the app before the authentication request occurred, such as the page or view they were on.
    resource	RECOMMENDED	The App ID URI of the target web API (secured resource). To find the App ID URI, in the Azure Portal, click Azure Active Directory, click Application registrations, open the application's Settings page, then click Properties. It may also be an external resource like https://graph.microsoft.com. This is required in one of either the authorization or token requests. To ensure fewer authentication prompts place it in the authorization request to ensure consent is received from the user.
    scope	IGNORED	For v1 Azure AD apps, scopes must be statically configured in the Azure Portal under the applications Settings, Required Permissions.
    prompt	OPTIONAL	Indicate the type of user interaction that is required.
        Valid values are:
            login: The user should be prompted to reauthenticate.
            select_account: The user is prompted to select an account, interrupting single sign on. The user may select an existing signed-in account, enter their credentials for a remembered account, or choose to use a different account altogether.
            consent: User consent has been granted, but needs to be updated. The user should be prompted to consent.
            admin_consent: An administrator should be prompted to consent on behalf of all users in their organization

    login_hint	OPTIONAL	Can be used to pre-fill the username/email address field of the sign-in page for the user, if you know their username ahead of time. Often apps use this parameter during reauthentication, having already extracted the username from a previous sign-in using the preferred_username claim.
    domain_hint	OPTIONAL	Provides a hint about the tenant or domain that the user should use to sign in. The value of the domain_hint is a registered domain for the tenant. If the tenant is federated to an on-premises directory, AAD redirects to the specified tenant federation server.
    code_challenge_method	RECOMMENDED	The method used to encode the code_verifier for the code_challenge parameter. Can be one of plain or S256. If excluded, code_challenge is assumed to be plaintext if code_challenge is included. Azure AAD v1.0 supports both plain and S256. For more information, see the PKCE RFC.
    code_challenge	RECOMMENDED Used to secure authorization code grants via Proof Key for Code Exchange (PKCE) from a native or public client. Required if code_challenge_method is included. For more information, see the PKCE RFC.

    /token

    tenant	required	The {tenant} value in the path of the request can be used to control who can sign into the application. The allowed values are tenant identifiers, for example, 8eaef023-2b34-4da1-9baa-8bc8c9d6a490 or contoso.onmicrosoft.com or common for tenant-independent tokens
    client_id	required	The Application Id assigned to your app when you registered it with Azure AD. You can find this in the Azure portal. The Application Id is displayed in the settings of the app registration.
    grant_type	required	Must be authorization_code for the authorization code flow.
    code	required	The authorization_code that you acquired in the previous section
    redirect_uri	required	A redirect_uriregistered on the client application.
    client_secret	required for web apps, not allowed for public clients	The application secret that you created in the Azure Portal for your app under Keys. It cannot be used in a native app (public client), because client_secrets cannot be reliably stored on devices. It is required for web apps and web APIs (all confidential clients), which have the ability to store the client_secret securely on the server side. The client_secret should be URL-encoded before being sent.
    resource	recommended	The App ID URI of the target web API (secured resource). To find the App ID URI, in the Azure Portal, click Azure Active Directory, click Application registrations, open the application's Settings page, then click Properties. It may also be an external resource like https://graph.microsoft.com. This is required in one of either the authorization or token requests. To ensure fewer authentication prompts place it in the authorization request to ensure consent is received from the user. If in both the authorization request and the token request, the resource` parameters must match.
    code_verifier	optional	The same code_verifier that was used to obtain the authorization_code. Required if PKCE was used in the authorization code grant request. For more information, see the PKCE RFC	


     urlpatterns = [
     url(r'^' + getattr(settings, 'LOGIN_URL', r'login/') + r'$', AzureADBackend().ad_login, name='azure_login'),
      url(r'^auth_complete/', AzureADSSOBackend().ad_authcomplete, name='azure_complete'),
     ]
'''

import logging

logger = logging.getLogger(__name__)


# version 2
# https://login.microsoftonline.com/{tenant} REQUIRED
# /oauth2/authorize?
# client_id=6731de76-14a6-49ae-97bc-6eba6914391e REQUIRED
# &response_type=code REQUIRED
# &redirect_uri=http%3A%2F%2Flocalhost%3A12345 RECOMMENDED
# & scope = openid REQUIRED
# &response_mode=query (query, fragment, or form_post) OPTIONAL
# &resource=https%3A%2F%2Fservice.contoso.com%2F RECOMMENDED
# &state=12345
# &prompt= OPTIONAL
# &login_hint= OPTIONAL

# TENANT = "Your tenant"  # Enter tenant name, e.g. contoso.onmicrosoft.com

class AzureADBackend(ModelBackend):
    RESPONSE_MODES = ['query', 'fragment', 'form_post']

    #RESPONSE_MODE = getattr(settings, 'RESPONSE_MODE', 'form_post')
    RESPONSE_MODE = 'form_post'

    CODE_CHALLENGE = getattr(settings, 'AZURE_AD_SSO_CODE_CHALLENGE', "S256")  # "plain"

    CREATE_USER = getattr(settings, 'AZURE_AD_SSO_AUTO_CREATE_USER', True)
    EXPIRATION = getattr(settings, 'AZURE_AD_SSO_EXPIRATION', 600)
    LOGIN_URL = getattr(settings, 'AZURE_AD_SSO_LOGIN_URL', settings.LOGIN_URL)  # if settings.LOGIN_URL else "/login"

    VERIFY = getattr(settings, 'AZURE_AD_SSO_VERIFY', True)

    POST_LOGOUT_REDIRECT_URI = getattr(settings, 'AZURE_AD_SSO_POST_LOGOUT_REDIRECT_URI', settings.LOGOUT_REDIRECT_URL)

    REDIRECT_URI = getattr(settings, 'AZURE_AD_SSO_REDIRECT_URL', settings.LOGIN_REDIRECT_URL)
    SCOPES = [
        'openid']  # can include email profile https://graph.microsoft.com mail.read calendars.read offline_access User.read ....
    # ["openid", "email", "profile"]
    # openid%20offline_access%20https%3A%2F%2Fgraph.microsoft.com%2Fuser.read

    TENANT_ID = getattr(settings, 'AZURE_AD_SSO_TENANT_ID', '')
    CLIENT_ID = getattr(settings, 'AZURE_AD_SSO_CLIENT_ID')
    RESOURCE = getattr(settings,
                       'AZURE_AD_SSO_RESOURCE')  # "https://graph.microsoft.com"  # Add the resource you want the access token for

    CLIENT_SECRET = getattr(settings, 'AZURE_AD_SSO_CLIENT_SECRET')

    AUTHORITY_HOST_URL = getattr(settings, 'AZURE_AD_SSO_HOST', "login.microsoftonline.com")

    AUTHORITY_URL = AUTHORITY_HOST_URL + '/' + TENANT_ID

    PROMPT = ''

    def __init__(self):
        super(AzureADBackend, self).__init__()
        self.UserModel = get_user_model()

    def get_token(self, id_token, nonce):
        jwt_data = {}
        info_url = 'https://{}/{}/v2.0/.well-known/openid-configuration'.format(self.AUTHORITY_HOST_URL, self.TENANT_ID)
        info = requests.get(info_url)
        if info.ok:
            info_data = info.json()
            jwks_uri = info_data.get('jwks_uri')
            supported = info_data.get('id_token_signing_alg_values_supported')
            if jwks_uri:
                key_response = requests.get(jwks_uri)
                # public_key = algorithms.RSAAlgorithm.from_jwk(key_response.content)
                key_data = key_response.json()
                unverified_data = jwt.get_unverified_header(id_token)
                if 'keys' in key_data:
                    for key in key_data['keys']:
                        if 'kid' in key and key['kid'] == unverified_data['kid']:
                            x5c = key['x5c']
                            cert = ''.join([
                                '-----BEGIN CERTIFICATE-----\n',
                                x5c[0],
                                '\n-----END CERTIFICATE-----\n',
                            ])
                            public_key = load_pem_x509_certificate(cert.encode(),
                                                                   default_backend()).public_key()
                            jwt_data = jwt.decode(id_token, public_key, algorithms=supported,
                                                  audience=self.CLIENT_ID)  # TODO CATCH jwt.invalidtoken/audience etc
        else:
            logger.error(
                "Failed to Get Signing Info from Endpoint {} with Status Code {}".format(info_url, info.status_code))
        if not jwt_data and not self.VERIFY:
            logger.warning("Could not Verify Public Key on JWT")
            jwt_data = jwt.decode(id_token, None, None)
        jwt_nonce = jwt_data.get('nonce', '')
        logger.info("checking jwt nonce {} is same as {}".format(jwt_nonce, nonce))
        if nonce == nonce:
            return jwt_data
        else:
            return {}

    # @never_cache
    @csrf_exempt
    def ad_authcomplete(self, request):
        try:
            code = getattr(request, 'POST').get('code')
            state = getattr(request, 'POST').get('state')
            # session.cycle_key()???
            nonce = request.session.get('nonce')
            # original_state = request.session.get('state')#doesn't work in many browsers
            # IE stores cookies State but chrome/firefox don't
            code_verifier = False
            if state:
                try:
                    state = TimestampSigner().unsign(state, max_age=self.EXPIRATION)
                except signing.SignatureExpired:
                    raise AzureADAuthFailed("Session Expired")
                try:
                    # request.session = SessionStore(session_key)
                    session = Session.objects.get(pk=state)
                    session_data = session.get_decoded()
                    nonce = session_data.get('nonce', '')
                    login_redirect_url = session_data.get('redirect_to', '/')
                    code_verifier = session_data.get('code_verifier', False)
                except Session.DoesNotExist:
                    logger.error("session {} does not exist".format(state))
                    raise AzureADAuthFailed("Session Not Found")
            if state and code and nonce:
                logger.info('requesting access token')
                token_url = ('https://{}/{}/oauth2/token').format(self.AUTHORITY_HOST_URL, self.TENANT_ID)
                request_parsed = urlparse(request.build_absolute_uri())
                redirect_uri = self.REDIRECT_URI
                if not bool(urlparse(redirect_uri).netloc):
                    redirect_uri = urlparse(redirect_uri)._replace(netloc=request_parsed.netloc,
                                                                   scheme=request_parsed.scheme).geturl()
                token_data = {'tenant': self.TENANT_ID, 'client_id': self.CLIENT_ID,
                              'grant_type': 'authorization_code', 'redirect_uri': redirect_uri,
                              'code': code, 'client_secret': self.CLIENT_SECRET}  # resource: '', code_verifier
                if code_verifier:
                    token_data.update({'code_verifier': code_verifier})
                # must contain client_assertion or client_secret
                token_response = requests.post(token_url, data=token_data)
                if token_response.status_code != 200:
                    logger.error('Unexpected token response {}'.format(token_response.status_code))
                else:
                    logger.info('token response 200')
                    token_json = token_response.json()
                    access_token = token_json.get('access_token')
                    id_token = token_json.get('id_token')
                    refresh_token = token_json.get('refresh_token')
                    if access_token and id_token and refresh_token:
                        # https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration
                        jwt_data = self.get_token(id_token, nonce)
                        '''
                        jwt is 
                            {'aud': 'CLIENT_ID', 
                            'iss': 'https://sts.windows.net/TENANT_ID/', 
                            'iat': 1554722639, 'nbf': 1554722639, 'exp': 1554726539,
                            'aio': '42ZgYKjZHfsz/ZXFOQvjzxV+m4+ddCjJTFJm2rhO+Srvj4eehXsB',
                            'amr': ['pwd'], 'family_name': 'Bloggs'
                            , 'given_name': 'Joe', 
                            'ipaddr': '00.000.000.000',
                            'name': 'Joe Bloggs',
                            'nonce': 'XXXXXXXX', 
                            'oid': '5a3af3d2-5fc8-4723-852c-f23878ca4da8',
                            'onprem_sid': 'S-1-5-21-132190885-2810042095-3450614141-66109', 
                            'sub': 'Xc807wMKX3yG0FtHknAxvfch8p8IgchPdHQ9TpVmGuA',
                            'tid': '694828a9-151a-45e1-9a5f-d75029018591', 
                            'unique_name': 'joebloggs@domain.co.uk', 
                            'upn': 'joebloggs@domain.co.uk', 
                            'uti': 'Yqcymsy9L0-rMA8ZNxk7AA', 'ver': '1.0'}
                        '''
                        email = jwt_data['upn']  # preferred_username ??
                        if jwt_data['nonce'] != nonce:
                            logger.error(
                                "response nonce {} does not match original {}".format(jwt_data['nonce'], nonce))
                        elif not email:
                            logger.error("email returned {}".format(email))
                        else:
                            last_name = jwt_data.get('family_name', None)
                            first_name = jwt_data.get('given_name', None)
                            try:
                                user = self.UserModel.objects.get(username=email, last_name=last_name,
                                                                  first_name=first_name)
                            except User.DoesNotExist:
                                try:
                                    user = User.objects.get(username=email)
                                    user.first_name = first_name
                                    user.last_name = last_name
                                    user.save()
                                except User.DoesNotExist:
                                    if self.CREATE_USER:
                                        user = User(username=email, email=email, last_name=last_name,
                                                    first_name=first_name)
                                        user.save()
                                    else:
                                        raise AzureADAuthFailed("{} Not Found".format(email))
                            if user is not None:
                                login(request, user, backend='azure_ad_sso.backends.AzureADBackend')
                                logger.info("login success redirecting back to {}".format(login_redirect_url))
                                request.session.modified = True
                                request.session.set_expiry(settings.SESSION_COOKIE_AGE)
                                return redirect(login_redirect_url)
                            # get longer access?
                            # access_data = token_data.copy()
                            # access_data.pop('code')
                            # access_data['refresh_token'] = refresh_token
                            # access_data['grant_type'] = 'refresh_token'
                            # access_response = requests.post(token_url, data=access_data)
            raise AzureADAuthFailed("Authentication Failed")
        except Exception as AuthException:
            raise AzureADAuthFailed("Authentication Error")

    @never_cache
    @csrf_exempt
    def ad_login(self, request):  # was (self,request
        '''
        Note
            Mixing HTTP and HTTPS on the same site is discouraged,
            therefore build_absolute_uri() will always generate an absolute URI
                 with the same scheme the current request has. If you need to redirect users to HTTPS, it’s best to let your Web server redirect all HTTP traffic to HTTPS.
            this needs to be quicker
        '''
        request_url = request.build_absolute_uri()
        request_parsed = urlparse(request_url)
        redirect_uri = self.REDIRECT_URI
        if hasattr(request, 'GET'):
            login_redirect_url = request.GET.get('next')
        if not login_redirect_url:
            login_redirect_url = request.META.get('HTTP_REFERER', '/')
        if not login_redirect_url:
            login_redirect_url = redirect_uri
        if not bool(urlparse(redirect_uri).netloc):  # relative url
            redirect_uri = urlparse(redirect_uri)._replace(netloc=request_parsed.netloc,
                                                           scheme=request_parsed.scheme).geturl()
        redirect_parsed = urlparse(redirect_uri)
        redirect_scheme = redirect_parsed.scheme
        request_scheme = request_parsed.scheme
        # match up url schemes to preserve cookies
        # if request.META['HTTP_X_REFERER'] or request.META['HTTP_X_FORWARDED_PROTO']:#REMOTE_ADDR
        #     request_proxy_scheme
        if redirect_scheme == 'https' and 'HTTP_X_FORWARDED_PROTO' in request.META and request.META[
            'HTTP_X_FORWARDED_PROTO'] != redirect_scheme:
            redirect_uri = urlparse(request_url)._replace(scheme=redirect_scheme).geturl()
        # upgrade to https
        if redirect_scheme != request_scheme:
            return HttpResponseRedirect(urlparse(request_url)._replace(scheme=redirect_scheme).geturl())
        if not request.session.session_key:
            request.session.create()
        request.session.set_expiry(self.EXPIRATION)
        nonce = str(uuid.uuid4())
        state = TimestampSigner().sign(request.session.session_key)
        request.session['nonce'] = nonce
        request.session.modified = True
        if login_redirect_url != request_url:
            # logger.info('setting redirect url to {}'.format(login_redirect_url))
            request.session['redirect_to'] = login_redirect_url  # url to direct to go back to after login
        # keywords
        # client_id, response_type, redirect_uri, response_mode, state, resource, scope,prompt,login_hint,domain_hint,code_challenge_method,code_challenge
        auth_url = ('{scheme}://{host}/{tenant_id}/oauth2/authorize?'
                    'client_id={client_id}&response_type=code'
                    '&redirect_uri={redirect_uri}'
                    '&scope={scopes}&state={state}&response_mode={response_mode}&nonce={nonce}')
        # if always authenticate set prompt to 'login'
        login_url = auth_url.format(scheme=request_scheme, host=self.AUTHORITY_HOST_URL, tenant_id=self.TENANT_ID,
                                    client_id=self.CLIENT_ID,
                                    redirect_uri=quote_plus(redirect_uri), scopes=quote_plus(' '.join(self.SCOPES)),
                                    state=state,
                                    response_mode=quote_plus(self.RESPONSE_MODE), nonce=nonce)
        # logger.info("Redirecting to %s" % login_url)
        if self.CODE_CHALLENGE:
            code_verifier = base64.urlsafe_b64encode(os.urandom(64)).rstrip(b'=')
            request.session['code_verifier'] = code_verifier.decode('ascii')
            # code_challenge = base64.urlsafe_b64encode(hmac.new(settings.SECRET_KEY.encode(), msg=code_verifier, digestmod=hashlib.sha256).digest()).rstrip(b"=")
            code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier).digest()).rstrip(b"=")
            login_url += "&code_challenge_method=S256&code_challenge={code_challenge}".format(
                code_challenge=quote_plus(code_challenge))
        '''
        if self.PROMPT and self.PROMPT in ('login', 'select_account', 'consent', 'admin_consent'):
            login_url += "&prompt={prompt}".format(prompt=quote_plus(self.PROMPT))
        '''
        # return redirect(login_url)
        return HttpResponseRedirect(login_url)

    @never_cache
    @csrf_exempt
    def ad_logout(self, request):
        logout(request)
        params = urlencode({'post_logout_redirect_uri': self.POST_LOGOUT_REDIRECT_URI})
        return redirect('{authority}/common/oauth2/authorize?{params}'.format(
            self.AUTHORITY_HOST_URL,
            params,
        ))
    # /logout...
