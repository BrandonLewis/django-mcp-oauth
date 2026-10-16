# Changelog

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
