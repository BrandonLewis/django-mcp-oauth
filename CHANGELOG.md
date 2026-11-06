# Changelog

## 0.1.1

Fix: a refresh now returns a new refresh token. 0.1.0 retired the presented
refresh token on every refresh but, through Authlib's default
`INCLUDE_NEW_REFRESH_TOKEN = False`, returned no replacement, so a client's
second refresh, one access-token lifetime after the first, always failed with
`invalid_grant` and every connection signed out about two token lifetimes after
it was made. The rotation grace window is unchanged.

## 0.1.0

First cut, extracted from two products that each carried a copy of this
authorization server and had started to drift. Behaviour is the union of the
two: the refresh-rotation grace window from one, and from the other the rule
that a token request naming no scope receives the client's full registered
scope rather than an empty one the resource server would reject. The product
hook (`MCP_OAUTH_AUTHORIZE_USER`) and the consent template are settings;
nothing in the app imports a product.

Requires Django 5.2 or newer and PyJWT 2.15 or newer: Django 5.1 is end-of-life
and every PyJWT 2.10 to 2.14 release carries published advisories. The floors are
what let a dependency audit of an adopter pass.
