# WebAuthn ruby library :key:

Make your Ruby/Rails web server become a conformant WebAuthn Relying Party.

[![Gem](https://img.shields.io/gem/v/webauthn.svg?style=flat-square)](https://rubygems.org/gems/webauthn)
[![Travis](https://img.shields.io/travis/cedarcode/webauthn-ruby/master.svg?style=flat-square)](https://travis-ci.org/cedarcode/webauthn-ruby)
[![Join the chat at https://gitter.im/cedarcode/webauthn-ruby](https://badges.gitter.im/cedarcode/webauthn-ruby.svg)](https://gitter.im/cedarcode/webauthn-ruby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

## What is WebAuthn?

WebAuthn (Web Authentication) is a W3C standard for secure public-key authentication on the Web supported by all leading browsers and platforms.

For more:

- WebAuthn [W3C Recommendation](https://www.w3.org/TR/webauthn/) (i.e. "The Standard")
- WebAuthn [intro](https://www.yubico.com/webauthn/) by Yubico
- WebAuthn [article](https://en.wikipedia.org/wiki/WebAuthn) in Wikipedia
- [Web Authentication API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API) in MDN
- WebAuthn [article with talk](https://developers.google.com/web/updates/2018/05/webauthn) in Google Developers

## Prerequisites

This ruby library will help your Ruby/Rails server act as a conforming [_Relying-Party_](https://www.w3.org/TR/webauthn/#relying-party), in WebAuthn terminology. But for the [_Registration_](https://www.w3.org/TR/webauthn/#registration) and [_Authentication_](https://www.w3.org/TR/webauthn/#authentication) ceremonies to fully work, you will also need to add two more pieces to the puzzle, a conforming [User Agent](https://www.w3.org/TR/webauthn/#conforming-user-agents) + [Authenticator](https://www.w3.org/TR/webauthn/#conforming-authenticators) pair.

A very small set of known conformant pairs are for example:

- Google Chrome for Android 70+ and Android's Fingerprint-based platform authenticator
- Microsoft Edge and Windows 10 platform authenticator
- Mozilla Firefox for Desktop and Yubico's Security Key roaming authenticator via USB

For a detailed picture about what is conformant and what not, you can refer to:

- [apowers313/fido2-webauthn-status](https://github.com/apowers313/fido2-webauthn-status)
- [FIDO certified products](https://fidoalliance.org/certification/fido-certified-products)


## Installation

Add this line to your application's Gemfile:

```ruby
gem 'webauthn'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install webauthn

## Usage

NOTE: You can find a working example on how to use this gem in a __Rails__ app in [webauthn-rails-demo-app](https://github.com/cedarcode/webauthn-rails-demo-app).

### Registration

#### Initiation phase

```ruby
credential_creation_options = WebAuthn.credential_creation_options

# Store the newly generated challenge somewhere so you can have it
# for the verification phase.
#
# You can read it from the resulting options:
credential_creation_options[:challenge]

# Send `credential_creation_options` to the browser, so that they can be used
# to call `navigator.credentials.create({ "publicKey": credentialCreationOptions })`
```

#### Verification phase

```ruby
# These should be ruby `String`s encoded as binary data, e.g. `Encoding:ASCII-8BIT`.
#
# If the user-agent is a web browser, you would use some encoding algorithm to send what
# `navigator.credentials.create` returned through the wire.
#
# Then you need to decode that data before passing it to the `#verify` method.
#
# E.g. in https://github.com/cedarcode/webauthn-rails-demo-app we use `Base64.strict_decode64`
# on the user-agent encoded data before calling `#verify`
attestation_object = "..."
client_data_json = "..."

attestation_response = WebAuthn::AuthenticatorAttestationResponse.new(
  attestation_object: attestation_object,
  client_data_json: client_data_json
)

# This value needs to match `window.location.origin` evaluated by
# the User Agent as part of the verification phase.
original_origin = "https://www.example.com"

begin
  attestation_response.verify(original_challenge, original_origin)

  # 1. Register the new user and
  # 2. Keep Credential ID and Credential Public Key under storage
  #    for future authentications
  #    Access by invoking:
  #      `attestation_response.credential.id`
  #      `attestation_response.credential.public_key`
rescue WebAuthn::VerificationError => e
  # Handle error
end
```

### Authentication

#### Initiation phase

Assuming you have the previously stored Credential ID, now in variable `credential_id`

```ruby
credential_request_options = WebAuthn.credential_request_options
credential_request_options[:allowCredentials] << { id: credential_id, type: "public-key" }

# Store the newly generated challenge somewhere so you can have it
# for the verification phase.
#
# You can read it from the resulting options:
credential_request_options[:challenge]

# Send `credential_request_options` to the browser, so that they can be used
# to call `navigator.credentials.get({ "publicKey": credentialRequestOptions })`
```

#### Verification phase

Assuming you have the previously stored Credential Public Key, now in variable `credential_public_key`

```ruby
# These should be ruby `String`s encoded as binary data, e.g. `Encoding:ASCII-8BIT`.
#
# If the user-agent is a web browser, you would use some encoding algorithm to send what
# `navigator.credentials.get` returned through the wire.
#
# Then you need to decode that data before passing it to the `#verify` method.
#
# E.g. in https://github.com/cedarcode/webauthn-rails-demo-app we use `Base64.strict_decode64`
# on the user-agent encoded data before calling `#verify`
authenticator_data = "..."
client_data_json = "..."
signature = "..."

assertion_response = WebAuthn::AuthenticatorAssertionResponse.new(
  authenticator_data: authenticator_data,
  client_data_json: client_data_json,
  signature: signature
)

# This value needs to match `window.location.origin` evaluated by
# the User Agent as part of the verification phase.
original_origin = "https://www.example.com"

# This hash must have the id and its corresponding public key of the
# previously stored credential for the user that is attempting to sign in.
allowed_credential = {
  id: credential_id,
  public_key: credential_public_key
}

begin
  assertion_response.verify(original_challenge, original_origin, allowed_credentials: [allowed_credential])

  # Sign in the user
rescue WebAuthn::VerificationError => e
  # Handle error
end
```

## Attestation Statement Formats

| Attestation Statement Format | Supported? |
| -------- | :--------: |
| packed (self attestation) | Yes |
| packed (x5c attestation) | Yes |
| packed (ECDAA attestation) | No |
| tpm (x5c attestation) | No |
| tpm (ECDAA attestation) | No |
| android-key | Yes |
| android-safetynet | Yes |
| fido-u2f | Yes |
| none | Yes |

NOTE: Be aware that it is up to you to do "trust path validation" (steps 15 and 16 in [Registering a new credential](https://www.w3.org/TR/webauthn/#registering-a-new-credential)) if that's a requirement of your Relying Party policy. The gem doesn't perform that validation for you right now.

## Testing Your Integration

The Webauthn spec requires for data that is signed and authenticated. As a result, it can be difficult to create valid test authenticator data when testing your integration. webauthn-ruby exposes [WebAuthn::FakeClient](https://github.com/cedarcode/webauthn-ruby/blob/master/lib/webauthn/fake_client.rb) for you to use in your tests. Example usage can be found in [webauthn-ruby/spec/webauthn/authenticator_assertion_response_spec.rb](https://github.com/cedarcode/webauthn-ruby/blob/master/spec/webauthn/authenticator_assertion_response_spec.rb).

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake` to run the tests and code-style checks. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

Some tests require stubbing time with [libfaketime](https://github.com/wolfcw/libfaketime) in order to pass, otherwise they're skipped. You can install this library with your package manager. Follow libfaketime's instructions for your OS to preload the library before running the tests, and use the `DONT_FAKE_MONOTONIC=1 FAKETIME_NO_CACHE=1` options. E.g. when installed via homebrew on macOS:
```shell
DYLD_INSERT_LIBRARIES=/usr/local/Cellar/libfaketime/2.9.7_1/lib/faketime/libfaketime.1.dylib DYLD_FORCE_FLAT_NAMESPACE=1 DONT_FAKE_MONOTONIC=1 FAKETIME_NO_CACHE=1 bundle exec rspec
```

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

### Commit message format

Each commit message follows the `<type>: <message>` format.

The "message" starts with lowercase and the "type" is one of:

* __build__: Changes that affect the build system or external dependencies
* __ci__: Changes to the CI configuration files and scripts
* __docs__: Documentation only changes
* __feat__: A new feature
* __fix__: A bug fix
* __perf__: A code change that improves performance
* __refactor__: A code change that neither fixes a bug nor adds a feature
* __style__: Changes that do not affect the meaning of the code (white-space, formatting, missing semi-colons, etc)
* __test__: Adding missing tests or correcting existing tests

Inspired in a subset of [Angular's Commit Message Guidelines](https://github.com/angular/angular/blob/master/CONTRIBUTING.md#-commit-message-guidelines).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/cedarcode/webauthn-ruby.

### Security

If you have discovered a security bug, please send an email to security@cedarcode.com instead of posting to the GitHub issue tracker.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
