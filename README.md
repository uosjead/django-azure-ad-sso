Django Azure AD OAuth2 SSO
==========================
Lightweight Non-Invasive Django Oauth2 Library that uses Azure Active Directory to authenticate users with no registration / login pages for a no frills Seamless Single-Sign-On for Django sites.

Uses existing Django Sessions to authenticate users against Azure Active Directory, returning users immediately to your site after authentication

requires Django > 1.11

this module does not support login over HTTP, HTTPS only must be set (see settings below)

add to settings.py

    AUTHENTICATION_BACKENDS = (
     'azure_ad_sso.backends.AzureADBackend',
     'django.contrib.auth.backends.ModelBackend',
    )

    MIDDLEWARE = (
    #...
        'django.contrib.sessions.middleware.SessionMiddleware', 
    )

    #the email is used as the Django Username

    AZURE_AD_SSO_TENANT_ID = 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX'
    
    AZURE_AD_SSO_CLIENT_ID = 'YYYYYYYY-YYYY-YYYY-YYYY-YYYYYYYYYYYY'

    AZURE_AD_SSO_LOGIN_URL = "/login"

    LOGIN_REDIRECT_URL = '/aad_authcomplete'

    AZURE_AD_SSO_HOST = 'login.microsoftonline.com'

    CSRF_TRUSTED_ORIGINS = [AZURE_AD_SSO_HOST]

    SECURE_COOKIE_DOMAIN = AZURE_AD_SSO_HOST

    ###optionally
    AZURE_AD_SSO_POST_LOGOUT_URL = '/where_to_go_after_logout'

    #optionally add this middleware to requied login for all views
    MIDDLEWARE = (
     ...
     "azure_ad_sso.middleware.SSORequireLoginMiddleware",
    )

    #these below are required to force https
    SECURE_SSL_REDIRECT = True
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

    #add these for good measure if you haven't already
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_HSTS_SECONDS = 10
    SECURE_HSTS_PRELOAD = True


add to urls.py

    from django.conf.urls import url
    from ...backends import AzureADBackend

    ...
    urlpatterns = [
        #...
            url(r'^login/$', AzureADBackend.ad_login),
            url(r'^auth_complete/', AzureADBackend.ad_authcomplete),

        #...
    ]

