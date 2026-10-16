from django.http import HttpResponse
from django.urls import path

from django_mcp_oauth.urls import oauth_urlpatterns, wellknown_urlpatterns

urlpatterns = [
    path("accounts/login/", lambda request: HttpResponse("login"), name="login"),
    *wellknown_urlpatterns,
    *oauth_urlpatterns,
]
