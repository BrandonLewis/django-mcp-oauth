from urllib.parse import urlencode

from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden, HttpResponseRedirect
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from authlib.oauth2 import OAuth2Error
from django_mcp_oauth import conf
from django_mcp_oauth.models import OAuth2Client
from django_mcp_oauth.server import ClientRegistration, authorization


def _access_denied_redirect(request):
    """Return a proper OAuth2 access_denied redirect when the product's gate
    denies an otherwise well-formed authorization request.

    We look up the client and validate the redirect_uri ourselves so we can
    produce the redirect without routing through Authlib's full flow (which
    raises InsecureTransportError for http:// request URIs in tests/dev).
    Returns an HttpResponseRedirect, or None if the client/redirect can't be
    validated (caller falls back to 403).
    """
    client_id = request.GET.get("client_id") or request.POST.get("client_id")
    redirect_uri = request.GET.get("redirect_uri") or request.POST.get("redirect_uri")
    state = request.GET.get("state") or request.POST.get("state")

    if not client_id:
        return None
    try:
        client = OAuth2Client.objects.get(client_id=client_id)
    except OAuth2Client.DoesNotExist:
        return None

    if redirect_uri:
        if not client.check_redirect_uri(redirect_uri):
            return None
    else:
        redirect_uri = client.get_default_redirect_uri()
        if not redirect_uri:
            return None

    params = [("error", "access_denied")]
    if state:
        params.append(("state", state))
    location = redirect_uri + ("&" if "?" in redirect_uri else "?") + urlencode(params)
    return HttpResponseRedirect(location)


@login_required
@require_http_methods(["GET", "POST"])
def authorize_view(request):
    if not conf.authorize_user(request.user):
        # Refuse to mint a token for an account the product has not
        # provisioned. For a well-formed request (valid client + redirect_uri)
        # produce a proper OAuth2 access_denied redirect; otherwise there is no
        # safe redirect destination and a 403 is the honest answer.
        redirect = _access_denied_redirect(request)
        if redirect is not None:
            return redirect
        return HttpResponseForbidden("Access denied: account not provisioned.")

    if request.method == "GET":
        try:
            grant = authorization.get_consent_grant(request=request, end_user=request.user)
        except OAuth2Error as error:
            return authorization.handle_error_response(request, error)
        return render(
            request,
            conf.consent_template(),
            {"grant": grant, "client": grant.client, "scope": grant.request.scope},
        )

    # POST = consent decision
    granted = request.POST.get("confirm") == "yes"
    grant_user = request.user if granted else None
    return authorization.create_authorization_response(request=request, grant_user=grant_user)


@csrf_exempt
@require_http_methods(["POST"])
def token_view(request):
    return authorization.create_token_response(request)


@csrf_exempt
@require_http_methods(["POST"])
def register_view(request):
    return authorization.create_endpoint_response(ClientRegistration.ENDPOINT_NAME, request)
