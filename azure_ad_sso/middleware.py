import re
from django.conf import settings
from django.contrib.auth.decorators import login_required
from .backends import AzureADBackend


import logging

logger = logging.getLogger(__name__)

# TODO manage for rest_framework, daphne
class SSORequireLoginMiddleware(object):
    """
    Add login_required decorator to all views except 3 urls - Login/ Callback and Logout Redirect Url
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.required = tuple(re.compile(url) for url in (r"/(.*)$",))
        self.exceptions = tuple(re.compile(  r"^/" +  url.strip("/") + "[/]?$") for url in (
             AzureADBackend.LOGIN_URL,
             AzureADBackend.REDIRECT_URI,
             AzureADBackend.POST_LOGOUT_REDIRECT_URI,
        ) if url)

    def __call__(self, request):
        # Code to be executed for each request before
        # the view (and later middleware) are called.

        response = self.get_response(request)

        # Code to be executed for each request/response after
        # the view is called.
        return response

    def process_view(self, request, view_func, view_args, view_kwargs):
        # No need to process URLs if user already logged in
        if request.user.is_authenticated:
            return None

        # An exception match should immediately return None
        for url in self.exceptions:
            if url.match(request.path):
                return None

        # Requests matching a restricted URL pattern are returned
        # wrapped with the login_required decorator
        for url in self.required:
            if url.match(request.path):
                return login_required(view_func)(request, *view_args, **view_kwargs)

        # Explicitly return None for all non-matching requests
        return None
    # def process_exception(self, request, exception):
    #    None or HttpResponse()
    # def process_template_response(self, request, response):
    #   response.context_data['key'] = 'value'
    #   return response