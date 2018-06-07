# Changelog

## [Unreleased]

### Added

- _Registration_ ceremony
  - `WebAuthn::AuthenticatorAttestationResponse.credential` returns the Credential Public Key for you to store it somehwere for future authentications
- _Authentication_ ceremony
  - `WebAuthn.credential_request_options` returns default options for you to initiate the _Authentication_
  - `WebAuthn::AuthenticatorAssertionResponse.valid?` can be used to validate the authenticator assertion. For now it validates:
    - Signature
    - Challenge
    - Origin
    - User presence
    - Ceremony Type
    - Relying-Party ID
- Works with ruby 2.4

### Changed

- _Registration_ ceremony
  - `WebAuthn::AuthenticatorAttestationResponse.valid?` now runs additional validations on the Credential Public Key

### Removed

- _Registration_ ceremony
  - `WebAuthn::AuthenticatorAttestationResponse.credential_id` (superseded by `WebAuthn::AuthenticatorAttestationResponse.credential`)

## [v0.1.0] - 2018-05-25

### Added

- _Registration_ ceremony:
  - `WebAuthn.credential_creation_options` returns default options for you to initiate the _Registration_
  - `WebAuthn::AuthenticatorAttestationResponse.valid?` can be used to validate fido-u2f attestations returned by the browser
- Works with ruby 2.5

[Unreleased]: https://github.com/cedarcode/webauthn-ruby/compare/v0.1.0...HEAD/
[v0.1.0]: https://github.com/cedarcode/webauthn-ruby/compare/v0.0.0...v0.1.0/
