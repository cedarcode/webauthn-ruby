# Changelog

## [v1.7.0] - 2018-11-08

### Added

- _Registration_ ceremony
  - `WebAuthn::AuthenticatorAttestationResponse` exposes attestation type and trust path via `#attestation_type` and `#attestation_trust_path` methods. Thank you @bdewater!

## [v1.6.0] - 2018-11-01

### Added

- `FakeAuthenticator` object is now exposed to help you test your WebAuthn implementation

## [v1.5.0] - 2018-10-23

### Added

- Works with ruby 2.3. Thank you @bdewater!

## [v1.4.0] - 2018-10-11

### Added

- _Registration_ ceremony
  - `WebAuthn::AuthenticatorAttestationResponse.valid?` supports `android-safetynet` attestation statements. Thank you @bdewater!

## [v1.3.0] - 2018-10-11

### Added

- _Registration_ ceremony
  - `WebAuthn::AuthenticatorAttestationResponse.valid?` supports `packed` attestation statements. Thank you @sorah!

## [v1.2.0] - 2018-10-08

### Added

- _Registration_ ceremony
  - `WebAuthn::AuthenticatorAttestationResponse.valid?` returns `true` if either UP or UV authenticator flags are present.
- _Authentication_ ceremony
  - `WebAuthn::AuthenticatorAssertionResponse.valid?` returns `true` if either UP or UV authenticator flags are present.

Note: Both additions should help making it compatible with Chrome for Android 70+/Android Fingerprint pair.

## [v1.1.0] - 2018-10-04

### Added

- _Registration_ ceremony
  - `WebAuthn::AuthenticatorAttestationResponse.valid?` optionally accepts rp_id. Thank you @sorah!
- _Authentication_ ceremony
  - `WebAuthn::AuthenticatorAssertionResponse.valid?` optionally accepts rp_id.

## [v1.0.0] - 2018-09-07

### Added

- _Authentication_ ceremony
  - Support multiple credentials per user by letting `WebAuthn::AuthenticatorAssertionResponse.valid?` receive multiple allowed credentials

### Changed

- _Registration_ ceremony
  - Use 32-byte challenge instead of 16-byte
- _Authentication_ ceremony
  - Use 32-byte challenge instead of 16-byte

## [v0.2.0] - 2018-06-08

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
    - Allowed Credential
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

[v1.7.0]: https://github.com/cedarcode/webauthn-ruby/compare/v1.6.0...v1.7.0/
[v1.6.0]: https://github.com/cedarcode/webauthn-ruby/compare/v1.5.0...v1.6.0/
[v1.5.0]: https://github.com/cedarcode/webauthn-ruby/compare/v1.4.0...v1.5.0/
[v1.4.0]: https://github.com/cedarcode/webauthn-ruby/compare/v1.3.0...v1.4.0/
[v1.3.0]: https://github.com/cedarcode/webauthn-ruby/compare/v1.2.0...v1.3.0/
[v1.2.0]: https://github.com/cedarcode/webauthn-ruby/compare/v1.1.0...v1.2.0/
[v1.1.0]: https://github.com/cedarcode/webauthn-ruby/compare/v1.0.0...v1.1.0/
[v1.0.0]: https://github.com/cedarcode/webauthn-ruby/compare/v0.2.0...v1.0.0/
[v0.2.0]: https://github.com/cedarcode/webauthn-ruby/compare/v0.1.0...v0.2.0/
[v0.1.0]: https://github.com/cedarcode/webauthn-ruby/compare/v0.0.0...v0.1.0/
