# Changelog

## 0.6.0 (unreleased)

### Breaking

#### Authentication

- `AuthConfirmationHandler::or` has been removed, use tuples, arrays, vecs or
  slices of confirmation handlers instead.
- `AuthConfirmationHandler::handle_confirmation` now takes `&mut self` instead
  of `self` and returns a boxed future.
- `login` methods now take a `ClientInfo` to allow customizing how the
  steam-vent presents itself to steam.
- Authenticating with an existing refresh token now requires parsing the raw
  token into a `AccessToken` before using it. And the naming has been fixed from
  using "access token" to "refresh token".

#### Connection

- The lower level function `one_with_header`, `on_with_header`,
  `send_with_kind`, `raw_send` and `raw_send_with_kind` have been removed from
  the `ConnectionTrait` in order to trim the public api.
- Information about the uses for a `Connection` (steam id, public ip, etc) no
  longer returns an `Option`.

#### Messages

- The `EncodableMessage` trait has been split op into `DecodableMessage` and
  `EncodableMessage` traits.
- The `NetMessage` trait has been split op into `SendableMessage` and
  `ReceivableMessage` traits.
- The `ServiceMethodRequest` trait has been split op into `ServiceMethodRequest`
  and `ServiceNotification` traits.

### Changes

- Steam guard confirmation now retries when an incorrect token is provided,
  `AuthConfirmationHandler::handle_confirmation` will be called once each
  attempts.
- The `ConnectionTrait` and related message traits have been moved to
  `steam-vent-core` (and are re-exported from `steam-vent`). This provides a
  smaller api surface for higher level wrappers (e.g. `steam-vent-chat`) to
  allow decoupling their version from `steam-vent` in most cases.
