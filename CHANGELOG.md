# Changelog

## [v3.1.0] - 2023-12-26

### Added

- Add support for optional `authenticator_attachment` in `PublicKeyCredential`. #370 [@8ma10s]

### Fixed

- Fix circular require warning between `webauthn/relying_party` and `webauthn/credential`. #389 [@bdewater]
- Correctly verify attestation that contains just a batch certificate that is present in the attestation root certificates. #406 [@santiagorodriguez96]

### Changed

- Inlined `base64` implementation. #402 [@olleolleolle]
- Raise a more descriptive error if input `challenge` is `nil` when verifying the `PublicKeyCredential`. #413 [@soartec-lab]

## [v3.0.0] - 2023-02-15

### Added

- Add the capability of handling appid extension #319 [@santiagorodriguez96]
- Add support for credential backup flags #378 [@santiagorodriguez96]
- Update dependencies to make gem compatible with OpenSSL 3.1 ([@bdewater],[@santiagorodriguez96])

## [v3.0.0.alpha2] - 2022-09-12

### Added

- Rebased support for multiple relying parties from v3.0.0.alpha1 on top of v2.5.2, the previous alpha version was based on v2.3.0 ([@bdewater])

### BREAKING CHANGES

- Bumped minimum required Ruby version to 2.5 ([@bdewater])

## [v3.0.0.alpha1] - 2020-06-27

### Added

- Ability to define multiple relying parties with the introduction of the `WebAuthn::RelyingParty` class ([@padulafacundo], [@brauliomartinezlm])

## [v2.5.2] - 2022-07-13

### Added

- Updated dependencies to make the gem compatible with openssl-3 [@ClearlyClaire]

## [v2.5.1] - 2022-03-20

### Added

- Updated openssl support to be ~>2.2 [@bdewater]

### Removed

- Removed dependency [secure_compare dependency] (https://rubygems.org/gems/secure_compare/versions/0.0.1) and use OpenSSL#secure_compare instead [@bdewater]

## [v2.5.0] - 2021-03-14

### Added

- Support 'apple' attestation statement format ([#343](https://github.com/cedarcode/webauthn-ruby/pull/343) / [@juanarias93], [@santiagorodriguez96])
- Allow specifying an array of ids as `allow_credentials:` for `FakeClient#get` method ([#335](https://github.com/cedarcode/webauthn-ruby/pull/335) / [@kingjan1999])

### Removed

- No longer accept "removed from the WebAuthn spec" options `rp: { icon: }` and `user: { icon: }` for `WebAuthn::Credential.options_for_create` method ([#326](https://github.com/cedarcode/webauthn-ruby/pull/326) / [@santiagorodriguez96])

## [v2.4.1] - 2021-02-15

### Fixed

- Fix verification of new credential if no attestation provided and 'None' type is not among configured `acceptable_attestation_types`. I.e. reject it instead of letting it go through.

## [v2.4.0] - 2020-09-03

### Added

- Support for ES256K credentials
- `FakeClient#get` accepts `user_handle:` keyword argument ([@lgarron])

## [v2.3.0] - 2020-06-27

### Added

- Ability to access extension outputs with `PublicKeyCredential#client_extension_outputs` and `PublicKeyCredential#authenticator_extension_outputs` ([@santiagorodriguez96])

## [v2.2.1] - 2020-06-06

### Fixed

- Fixed compatibility with OpenSSL-C (libssl) v1.0.2 ([@santiagorodriguez96])

## [v2.2.0] - 2020-03-14

### Added

- Verification step that checks the received credential public key algorithm during registration matches one of the configured algorithms
- [EXPERIMENTAL] Attestation trustworthiness verification default steps for "tpm", "android-key" and "android-safetynet" ([@bdewater], [@padulafacundo]). Still manual configuration needed for "packed" and "fido-u2f".

Note: Expect possible breaking changes for "EXPERIMENTAL" features.

## [v2.1.0] - 2019-12-30

### Added

- Ability to convert stored credential public key back to a ruby object with `WebAuthn::PublicKey.deserialize(stored_public_key)`, included the validation during de-serialization ([@ssuttner], [@padulafacundo])
- Improved TPM attestation validation by checking "Subject Alternative Name" ([@bdewater])
- Improved SafetyNet attestation validation by checking timestamp ([@padulafacundo])
- [EXPERIMENTAL] Ability to optionally "Assess the attestation trustworthiness" during registration by setting `acceptable_attestation_types` and `attestation_root_certificates_finders` configuration values ([@padulafacundo])
- Ruby 2.7 support without warnings

Note: Expect possible breaking changes for "EXPERIMENTAL" features.

## [v2.0.0] - 2019-10-03

### Added

- Smarter new public API methods:
  - `WebAuthn.generate_user_id`
  - `WebAuthn::Credential.options_for_create`
  - `WebAuthn::Credential.options_for_get`
  - `WebAuthn::Credential.from_create`
  - `WebAuthn::Credential.from_get`
  - All the above automatically handle encoding/decoding for necessary values. The specific encoding scheme can
    be set (or even turned off) in `WebAutnn.configuration.encoding=`. Defaults to `:base64url`.
- `WebAuthn::FakeClient#get` better fakes a real client by including `userHandle` in the returned hash.
- Expose AAGUID and attestationCertificateKey for MDS lookup during attestation ([@bdewater])

### Changed

- `WebAuthn::AuthenticatorAssertionResponse#verify` no longer accepts `allowed_credentials:` keyword argument.
Please replace with `public_key:` and `sign_count:` keyword arguments. If you're not performing sign count
verification, signal opt-out with `sign_count: false`.

- `WebAuthn::FakeClient#create` and `WebAuthn::FakeClient#get` better fakes a real client by using lowerCamelCase
string keys instead of snake_case symbol keys in the returned hash.

- `WebAuthn::FakeClient#create` and `WebAuthn::FakeClient#get` better fakes a real client by not padding the
returned base64url-encoded `id` value.

### Deprecated

- `WebAuthn.credential_creation_options` method. Please consider using `WebAuthn::Credential.options_for_create`.
- `WebAuthn.credential_request_options` method. Please consider using `WebAuthn::Credential.options_for_get`.

### Removed

- `WebAuthn::AuthenticatorAssertionResponse.new` no longer accepts `credential_id`. No replacement needed, just don't
pass it.

### BREAKING CHANGES

- `WebAuthn::AuthenticatorAssertionResponse.new` no longer accepts `credential_id`. No replacement needed, just don't
pass it.

- `WebAuthn::AuthenticatorAssertionResponse#verify` no longer accepts `allowed_credentials:` keyword argument.
Please replace with `public_key:` and `sign_count:` keyword arguments. If you're not performing sign count
verification, signal opt-out with `sign_count: false`.

- `WebAuthn::FakeClient#create` and `WebAuthn::FakeClient#get` better fakes a real client by using lowerCamelCase
string keys instead of snake_case symbol keys in the returned hash.

- `WebAuthn::FakeClient#create` and `WebAuthn::FakeClient#get` better fakes a real client by not padding the
returned base64url-encoded `id` value.

## [v1.18.0] - 2019-07-27

### Added

- Ability to migrate U2F credentials to WebAuthn ([#211](https://github.com/cedarcode/webauthn-ruby/pull/211)) ([@bdewater] + [@jdongelmans])
- Ability to skip attestation statement verification ([#219](https://github.com/cedarcode/webauthn-ruby/pull/219)) ([@MaximeNdutiye])
- Ability to configure default credential options timeout ([#243](https://github.com/cedarcode/webauthn-ruby/pull/243)) ([@MaximeNdutiye])
- AttestedCredentialData presence verification ([#237](https://github.com/cedarcode/webauthn-ruby/pull/237))
- FakeClient learns how to increment sign count ([#225](https://github.com/cedarcode/webauthn-ruby/pull/225))

### Fixed

- Properly verify SafetyNet certificates from input ([#233](https://github.com/cedarcode/webauthn-ruby/pull/233)) ([@bdewater])
- FakeClient default origin URL ([#242](https://github.com/cedarcode/webauthn-ruby/pull/242)) ([@kalebtesfay])

## [v1.17.0] - 2019-06-18

### Added

- Support ES384, ES512, PS384, PS512, RS384 and RS512 credentials. Off by default. Enable by adding any of them to `WebAuthn.configuration.algorithms` array ([@bdewater])
- Support [Signature Counter](https://www.w3.org/TR/webauthn/#signature-counter) verification ([@bdewater])

## [v1.16.0] - 2019-06-13

### Added

- Ability to enforce [user verification](https://www.w3.org/TR/webauthn/#user-verification) with extra argument in the `#verify` method.
- Support RS1 (RSA w/ SHA-1) credentials. Off by default. Enable by adding `"RS1"` to `WebAuthn.configuration.algorithms` array.
- Support PS256 (RSA Probabilistic Signature Scheme w/ SHA-256) credentials. On by default ([@bdewater])

## [v1.15.0] - 2019-05-16

### Added

- Ability to configure Origin, RP ID and RP Name via `WebAuthn.configure`

## [v1.14.0] - 2019-04-25

### Added

- Support 'tpm' attestation statement
- Support RS256 credential public key

## [v1.13.0] - 2019-04-09

### Added

- Verify 'none' attestation statement is really empty.
- Verify 'packed' attestation statement certificates start/end dates.
- Verify 'packed' attestation statement signature algorithm.
- Verify 'fiod-u2f attestation statement AAGUID is zeroed out ([@bdewater])
- Verify 'android-key' attestation statement signature algorithm.
- Verify assertion response signature algorithm.
- Verify collectedClientData.tokenBinding format.
- `WebAuthn.credential_creation_options` now accept `rp_name`, `user_id`, `user_name` and `display_name` as keyword arguments ([@bdewater])

## [v1.12.0] - 2019-04-03

### Added

- Verification of the attestation certificate public key curve for `fido-u2f` attestation statements.

### Changed

- `Credential#public_key` now returns the COSE_Key formatted version of the credential public key, instead of the
uncompressed EC point format.

Note #1: A `Credential` instance is what is returned in `WebAuthn::AuthenticatorAttestationResponse#credential`.

Note #2: You don't need to do any convesion before passing the public key in `AuthenticatorAssertionResponse#verify`'s
`allowed_credentials` argument, `#verify` is backwards-compatible and will handle both public key formats properly.

## [v1.11.0] - 2019-03-15

### Added

- `WebAuthn::AuthenticatorAttestationResponse#verify` supports `android-key` attestation statements ([@bdewater])

### Fixed

- Verify matching AAGUID if needed when verifying `packed` attestation statements ([@bdewater])

## [v1.10.0] - 2019-03-05

### Added

- Parse and make AuthenticatorData's extensionData available

## [v1.9.0] - 2019-02-22

### Added

- Added `#verify`, which can be used for getting a meaningful error raised in case of a verification error, as opposed to `#valid?` which returns `false`

## [v1.8.0] - 2019-01-17

### Added

- Make challenge validation inside `#valid?` method resistant to timing attacks (@tomek-bt)
- Support for ruby 2.6

### Changed

- Make current raised exception errors a bit more meaningful to aid debugging

## [v1.7.0] - 2018-11-08

### Added

- _Registration_ ceremony
  - `WebAuthn::AuthenticatorAttestationResponse` exposes attestation type and trust path via `#attestation_type` and `#attestation_trust_path` methods ([@bdewater])

## [v1.6.0] - 2018-11-01

### Added

- `FakeAuthenticator` object is now exposed to help you test your WebAuthn implementation

## [v1.5.0] - 2018-10-23

### Added

- Works with ruby 2.3 ([@bdewater])

## [v1.4.0] - 2018-10-11

### Added

- _Registration_ ceremony
  - `WebAuthn::AuthenticatorAttestationResponse.valid?` supports `android-safetynet` attestation statements ([@bdewater])

## [v1.3.0] - 2018-10-11

### Added

- _Registration_ ceremony
  - `WebAuthn::AuthenticatorAttestationResponse.valid?` supports `packed` attestation statements ([@sorah])

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
  - `WebAuthn::AuthenticatorAttestationResponse.valid?` optionally accepts rp_id ([@sorah])
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

[v3.1.0]: https://github.com/cedarcode/webauthn-ruby/compare/v3.0.0...v3.1.0/
[v3.0.0]: https://github.com/cedarcode/webauthn-ruby/compare/2-stable...v3.0.0/
[v3.0.0.alpha2]: https://github.com/cedarcode/webauthn-ruby/compare/2-stable...v3.0.0.alpha2/
[v3.0.0.alpha1]: https://github.com/cedarcode/webauthn-ruby/compare/v2.3.0...v3.0.0.alpha1
[v2.5.2]: https://github.com/cedarcode/webauthn-ruby/compare/v2.5.1...v2.5.2/
[v2.5.1]: https://github.com/cedarcode/webauthn-ruby/compare/v2.5.0...v2.5.1/
[v2.5.0]: https://github.com/cedarcode/webauthn-ruby/compare/v2.4.1...v2.5.0/
[v2.4.1]: https://github.com/cedarcode/webauthn-ruby/compare/v2.4.0...v2.4.1/
[v2.4.0]: https://github.com/cedarcode/webauthn-ruby/compare/v2.3.0...v2.4.0/
[v2.3.0]: https://github.com/cedarcode/webauthn-ruby/compare/v2.2.1...v2.3.0/
[v2.2.1]: https://github.com/cedarcode/webauthn-ruby/compare/v2.2.0...v2.2.1/
[v2.2.0]: https://github.com/cedarcode/webauthn-ruby/compare/v2.1.0...v2.2.0/
[v2.1.0]: https://github.com/cedarcode/webauthn-ruby/compare/v2.0.0...v2.1.0/
[v2.0.0]: https://github.com/cedarcode/webauthn-ruby/compare/v1.18.0...v2.0.0/
[v1.18.0]: https://github.com/cedarcode/webauthn-ruby/compare/v1.17.0...v1.18.0/
[v1.17.0]: https://github.com/cedarcode/webauthn-ruby/compare/v1.16.0...v1.17.0/
[v1.16.0]: https://github.com/cedarcode/webauthn-ruby/compare/v1.15.0...v1.16.0/
[v1.15.0]: https://github.com/cedarcode/webauthn-ruby/compare/v1.14.0...v1.15.0/
[v1.14.0]: https://github.com/cedarcode/webauthn-ruby/compare/v1.13.0...v1.14.0/
[v1.13.0]: https://github.com/cedarcode/webauthn-ruby/compare/v1.12.0...v1.13.0/
[v1.12.0]: https://github.com/cedarcode/webauthn-ruby/compare/v1.11.0...v1.12.0/
[v1.11.0]: https://github.com/cedarcode/webauthn-ruby/compare/v1.10.0...v1.11.0/
[v1.10.0]: https://github.com/cedarcode/webauthn-ruby/compare/v1.9.0...v1.10.0/
[v1.9.0]: https://github.com/cedarcode/webauthn-ruby/compare/v1.8.0...v1.9.0/
[v1.8.0]: https://github.com/cedarcode/webauthn-ruby/compare/v1.7.0...v1.8.0/
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

[@brauliomartinezlm]: https://github.com/brauliomartinezlm
[@bdewater]: https://github.com/bdewater
[@jdongelmans]: https://github.com/jdongelmans
[@kalebtesfay]: https://github.com/kalebtesfay
[@MaximeNdutiye]: https://github.com/MaximeNdutiye
[@sorah]: https://github.com/sorah
[@ssuttner]: https://github.com/ssuttner
[@padulafacundo]: https://github.com/padulafacundo
[@santiagorodriguez96]: https://github.com/santiagorodriguez96
[@lgarron]: https://github.com/lgarron
[@juanarias93]: https://github.com/juanarias93
[@kingjan1999]: https://github.com/@kingjan1999
[@jdongelmans]: https://github.com/jdongelmans
[@petergoldstein]: https://github.com/petergoldstein
[@ClearlyClaire]: https://github.com/ClearlyClaire
