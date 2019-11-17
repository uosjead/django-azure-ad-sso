from django.conf.urls import url
from django.conf import settings
from .backends import AzureADBackend
#TODO configure for include
urlpatterns = [
    url(r'^login[/]?', AzureADBackend().ad_login, name='azure_sso_login'),
    url(r'^auth_complete[/]?', AzureADBackend().ad_authcomplete, name='azure_sso_complete'),
]