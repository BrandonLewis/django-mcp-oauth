# Changelog

## 0.1.1

- Fix: a client that registered without `scope` (optional under RFC 7591, and
  omitted by several MCP clients) was stored with an empty scope, so every
  token it got was clamped to "" and the resource server rejected it as
  `insufficient_scope`. Sign-in looked successful, but the connection never
  worked. Registration now stores `MCP_OAUTH_SCOPE` when none is given, and an
  existing client with no stored scope reads as holding it, so clients that
  already registered start working without re-registering.

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
