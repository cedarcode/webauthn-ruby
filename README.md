__Note__: You are viewing the README for the development version of webauthn-ruby.
For the current release version see https://github.com/cedarcode/webauthn-ruby/blob/2-stable/README.md.

# webauthn-ruby

![banner](assets/webauthn-ruby.png)

[![Gem](https://img.shields.io/gem/v/webauthn.svg?style=flat-square)](https://rubygems.org/gems/webauthn)
[![Build](https://github.com/cedarcode/webauthn-ruby/actions/workflows/build.yml/badge.svg?branch=master)](https://github.com/cedarcode/webauthn-ruby/actions/workflows/build.yml)
[![Conventional Commits](https://img.shields.io/badge/Conventional%20Commits-1.0.0-informational.svg?style=flat-square)](https://conventionalcommits.org)
[![Join the chat at https://gitter.im/cedarcode/webauthn-ruby](https://badges.gitter.im/cedarcode/webauthn-ruby.svg)](https://gitter.im/cedarcode/webauthn-ruby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

> WebAuthn ruby server library

Makes your Ruby/Rails web server become a functional [WebAuthn Relying Party](https://www.w3.org/TR/webauthn/#webauthn-relying-party).

Takes care of the [server-side operations](https://www.w3.org/TR/webauthn/#rp-operations) needed to
[register](https://www.w3.org/TR/webauthn/#registration) or [authenticate](https://www.w3.org/TR/webauthn/#authentication)
a user's [public key credential](https://www.w3.org/TR/webauthn/#public-key-credential) (also called a "passkey"), including the necessary cryptographic checks.

## Table of Contents

- [Security](#security)
- [Background](#background)
- [Prerequisites](#prerequisites)
- [Install](#install)
- [Usage](#usage)
- [API](#api)
- [Attestation Statement Formats](#attestation-statement-formats)
- [Testing Your Integration](#testing-your-integration)
- [Contributing](#contributing)
- [License](#license)

## Security

Please report security vulnerabilities to security@cedarcode.com.

_More_: [SECURITY](SECURITY.md)

## Background

### What is WebAuthn?

WebAuthn (Web Authentication) is a W3C standard for secure public-key authentication on the Web supported by all leading browsers and platforms.

#### Good Intros

- [Guide to Web Authentication](https://webauthn.guide) by Duo
- [What is WebAuthn?](https://www.yubico.com/webauthn/) by Yubico

#### In Depth

- WebAuthn [W3C Recommendation](https://www.w3.org/TR/webauthn/) (i.e. "The Standard")
- [Web Authentication API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API) in MDN
- How to use WebAuthn in native [Android](https://developers.google.com/identity/fido/android/native-apps) or [macOS/iOS/iPadOS](https://developer.apple.com/documentation/authenticationservices/public-private_key_authentication) apps.
- [Security Benefits for WebAuthn Servers (a.k.a Relying Parties)](https://www.w3.org/TR/webauthn/#sctn-rp-benefits)

## Prerequisites

This ruby library will help your Ruby/Rails server act as a conforming [_Relying-Party_](https://www.w3.org/TR/webauthn/#relying-party), in WebAuthn terminology. But for the [_Registration_](https://www.w3.org/TR/webauthn/#registration) and [_Authentication_](https://www.w3.org/TR/webauthn/#authentication) ceremonies to fully work, you will also need to add two more pieces to the puzzle, a conforming [User Agent](https://www.w3.org/TR/webauthn/#conforming-user-agents) + [Authenticator](https://www.w3.org/TR/webauthn/#conforming-authenticators) pair.

Known conformant pairs are, for example:

- Google Chrome for Android 70+ and Android's Fingerprint-based platform authenticator
- Microsoft Edge and Windows 10 platform authenticator
- Mozilla Firefox for Desktop and Yubico's Security Key roaming authenticator via USB
- Safari in iOS 13.3+ and YubiKey 5 NFC via NFC

For a complete list:

- User Agents (Clients): [Can I Use: Web Authentication API](https://caniuse.com/#search=webauthn)
- Authenticators: [FIDO certified products](https://fidoalliance.org/certification/fido-certified-products) (search for Type=Authenticator and Specification=FIDO2)

## Install

Add this line to your application's Gemfile:

```ruby
gem 'webauthn'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install webauthn

## Usage

You can find a working example on how to use this gem in a pasword-less login in a __Rails__ app in [webauthn-rails-demo-app](https://github.com/cedarcode/webauthn-rails-demo-app). If you want to see an example on how to use this gem as a second factor authenticator in a __Rails__ application instead, you can check it in [webauthn-2fa-rails-demo](https://github.com/cedarcode/webauthn-2fa-rails-demo).

If you are migrating an existing application from the legacy FIDO U2F JavaScript API to WebAuthn, also refer to
[`docs/u2f_migration.md`](docs/u2f_migration.md).

### Configuration

If you have a multi-tenant application or just need to configure WebAuthn differently for separate parts of your application (e.g. if your users authenticate to different subdomains in the same application), we strongly recommend you look at this [Advanced Configuration](docs/advanced_configuration.md) section instead of this.

For a Rails application this would go in `config/initializers/webauthn.rb`.

```ruby
WebAuthn.configure do |config|
  # This value needs to match `window.location.origin` evaluated by
  # the User Agent during registration and authentication ceremonies.
  config.origin = "https://auth.example.com"

  # Relying Party name for display purposes
  config.rp_name = "Example Inc."

  # Optionally configure a client timeout hint, in milliseconds.
  # This hint specifies how long the browser should wait for any
  # interaction with the user.
  # This hint may be overridden by the browser.
  # https://www.w3.org/TR/webauthn/#dom-publickeycredentialcreationoptions-timeout
  # config.credential_options_timeout = 120_000

  # You can optionally specify a different Relying Party ID
  # (https://www.w3.org/TR/webauthn/#relying-party-identifier)
  # if it differs from the default one.
  #
  # In this case the default would be "auth.example.com", but you can set it to
  # the suffix "example.com"
  #
  # config.rp_id = "example.com"

  # Configure preferred binary-to-text encoding scheme. This should match the encoding scheme
  # used in your client-side (user agent) code before sending the credential to the server.
  # Supported values: `:base64url` (default), `:base64` or `false` to disable all encoding.
  #
  # config.encoding = :base64url

  # Possible values: "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512", "RS1"
  # Default: ["ES256", "PS256", "RS256"]
  #
  # config.algorithms << "ES384"
end
```

### Credential Registration

> The ceremony where a user, a Relying Party, and the user’s client (containing at least one authenticator) work in concert to create a public key credential and associate it with the user’s Relying Party account. Note that this includes employing a test of user presence or user verification.
> [[source](https://www.w3.org/TR/webauthn-2/#registration-ceremony)]

#### Initiation phase

```ruby
# Generate and store the WebAuthn User ID the first time the user registers a credential
if !user.webauthn_id
  user.update!(webauthn_id: WebAuthn.generate_user_id)
end

options = WebAuthn::Credential.options_for_create(
  user: { id: user.webauthn_id, name: user.name },
  exclude: user.credentials.map { |c| c.webauthn_id }
)

# Store the newly generated challenge somewhere so you can have it
# for the verification phase.
session[:creation_challenge] = options.challenge

# Send `options` back to the browser, so that they can be used
# to call `navigator.credentials.create({ "publicKey": options })`
#
# You can call `options.as_json` to get a ruby hash with a JSON representation if needed.

# If inside a Rails controller, `render json: options` will just work.
# I.e. it will encode and convert the options to JSON automatically.

# For your frontend code, you might find @github/webauthn-json npm package useful.
# Especially for handling the necessary decoding of the options, and sending the
# `PublicKeyCredential` object back to the server.
```

#### Verification phase

```ruby
# Assuming you're using @github/webauthn-json package to send the `PublicKeyCredential` object back
# in params[:publicKeyCredential]:
webauthn_credential = WebAuthn::Credential.from_create(params[:publicKeyCredential])

begin
  webauthn_credential.verify(session[:creation_challenge])

  # Store Credential ID, Credential Public Key and Sign Count for future authentications
  user.credentials.create!(
    webauthn_id: webauthn_credential.id,
    public_key: webauthn_credential.public_key,
    sign_count: webauthn_credential.sign_count
  )
rescue WebAuthn::Error => e
  # Handle error
end
```

### Credential Authentication

> The ceremony where a user, and the user’s client (containing at least one authenticator) work in concert to cryptographically prove to a Relying Party that the user controls the credential private key associated with a previously-registered public key credential (see Registration). Note that this includes a test of user presence or user verification. [[source](https://www.w3.org/TR/webauthn-2/#authentication-ceremony)]

#### Initiation phase

```ruby
options = WebAuthn::Credential.options_for_get(allow: user.credentials.map { |c| c.webauthn_id })

# Store the newly generated challenge somewhere so you can have it
# for the verification phase.
session[:authentication_challenge] = options.challenge

# Send `options` back to the browser, so that they can be used
# to call `navigator.credentials.get({ "publicKey": options })`

# You can call `options.as_json` to get a ruby hash with a JSON representation if needed.

# If inside a Rails controller, `render json: options` will just work.
# I.e. it will encode and convert the options to JSON automatically.

# For your frontend code, you might find @github/webauthn-json npm package useful.
# Especially for handling the necessary decoding of the options, and sending the
# `PublicKeyCredential` object back to the server.
```

#### Verification phase

You need to look up the stored credential for a user by matching the `id` attribute from the PublicKeyCredential 
interface returned by the browser to the stored `credential_id`. The corresponding `public_key` and `sign_count` 
attributes must be passed as keyword arguments to the `verify` method call.

```ruby
# Assuming you're using @github/webauthn-json package to send the `PublicKeyCredential` object back
# in params[:publicKeyCredential]:
webauthn_credential = WebAuthn::Credential.from_get(params[:publicKeyCredential])

stored_credential = user.credentials.find_by(webauthn_id: webauthn_credential.id)

begin
  webauthn_credential.verify(
    session[:authentication_challenge],
    public_key: stored_credential.public_key,
    sign_count: stored_credential.sign_count
  )

  # Update the stored credential sign count with the value from `webauthn_credential.sign_count`
  stored_credential.update!(sign_count: webauthn_credential.sign_count)

  # Continue with successful sign in or 2FA verification...

rescue WebAuthn::SignCountVerificationError => e
  # Cryptographic verification of the authenticator data succeeded, but the signature counter was less then or equal
  # to the stored value. This can have several reasons and depending on your risk tolerance you can choose to fail or
  # pass authentication. For more information see https://www.w3.org/TR/webauthn/#sign-counter
rescue WebAuthn::Error => e
  # Handle error
end
```

### Extensions

> The mechanism for generating public key credentials, as well as requesting and generating Authentication assertions, as defined in Web Authentication API, can be extended to suit particular use cases. Each case is addressed by defining a registration extension and/or an authentication extension.

> When creating a public key credential or requesting an authentication assertion, a WebAuthn Relying Party can request the use of a set of extensions. These extensions will be invoked during the requested ceremony if they are supported by the WebAuthn Client and/or the WebAuthn Authenticator. The Relying Party sends the client extension input for each extension in the get() call (for authentication extensions) or create() call (for registration extensions) to the WebAuthn client. [[source](https://www.w3.org/TR/webauthn-2/#sctn-extensions)]

Extensions can be requested in the initiation phase in both Credential Registration and Authentication ceremonies by adding the extension parameter when generating the options for create/get:

```ruby
# Credential Registration
creation_options = WebAuthn::Credential.options_for_create(
  user: { id: user.webauthn_id, name: user.name },
  exclude: user.credentials.map { |c| c.webauthn_id },
  extensions: { appidExclude: domain.to_s }
)

# OR

# Credential Authentication
options = WebAuthn::Credential.options_for_get(
  allow: user.credentials.map { |c| c.webauthn_id },
  extensions: { appid: domain.to_s }
)
```

Consequently, after these `options` are sent to the WebAuthn client:

> The WebAuthn client performs client extension processing for each extension that the client supports, and augments the client data as specified by each extension, by including the extension identifier and client extension output values.

> For authenticator extensions, as part of the client extension processing, the client also creates the CBOR authenticator extension input value for each extension (often based on the corresponding client extension input value), and passes them to the authenticator in the create() call (for registration extensions) or the get() call (for authentication extensions).

> The authenticator, in turn, performs additional processing for the extensions that it supports, and returns the CBOR authenticator extension output for each as specified by the extension. Part of the client extension processing for authenticator extensions is to use the authenticator extension output as an input to creating the client extension output. [[source](https://www.w3.org/TR/webauthn-2/#sctn-extensions)]

Finally, you can check the values returned for each extension by calling `client_extension_outputs` and `authenticator_extension_outputs` respectively.
For example, following the initialization phase for the Credential Authentication ceremony specified in the above example:

```ruby
webauthn_credential = WebAuthn::Credential.from_get(credential_get_result_hash)

webauthn_credential.client_extension_outputs #=> { "appid" => true }
webauthn_credential.authenticator_extension_outputs #=> nil
```

A list of all currently defined extensions:

  - [Last published version](https://www.w3.org/TR/webauthn-2/#sctn-defined-extensions)
  - [Next version (in draft)](https://w3c.github.io/webauthn/#sctn-defined-extensions)

## API

#### `WebAuthn.generate_user_id`

Generates a [WebAuthn User Handle](https://www.w3.org/TR/webauthn-2/#user-handle) that follows the WebAuthn spec recommendations.

```ruby
WebAuthn.generate_user_id # "lWoMZTGf_ml2RoY5qPwbwrkxrvTqWjGOxEoYBgxft3zG-LlrICvE-y8bxFi06zMyIOyNsJoWx4Fa2TOqoRmnxA"
```

#### `WebAuthn::Credential.options_for_create(options)`

Helper method to build the necessary [PublicKeyCredentialCreationOptions](https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialcreationoptions)
to be used in the client-side code to call `navigator.credentials.create({ "publicKey": publicKeyCredentialCreationOptions })`.

```ruby
creation_options = WebAuthn::Credential.options_for_create(
  user: { id: user.webauthn_id, name: user.name }
  exclude: user.credentials.map { |c| c.webauthn_id }
)

# Store the newly generated challenge somewhere so you can have it
# for the verification phase.
session[:creation_challenge] = creation_options.challenge

# Send `creation_options` back to the browser, so that they can be used
# to call `navigator.credentials.create({ "publicKey": creationOptions })`
#
# You can call `creation_options.as_json` to get a ruby hash with a JSON representation if needed.

# If inside a Rails controller, `render json: creation_options` will just work.
# I.e. it will encode and convert the options to JSON automatically.
```

#### `WebAuthn::Credential.options_for_get([options])`

Helper method to build the necessary [PublicKeyCredentialRequestOptions](https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialrequestoptions)
to be used in the client-side code to call `navigator.credentials.get({ "publicKey": publicKeyCredentialRequestOptions })`.

```ruby
request_options = WebAuthn::Credential.options_for_get(allow: user.credentials.map { |c| c.webauthn_id })

# Store the newly generated challenge somewhere so you can have it
# for the verification phase.
session[:authentication_challenge] = request_options.challenge

# Send `request_options` back to the browser, so that they can be used
# to call `navigator.credentials.get({ "publicKey": requestOptions })`

# You can call `request_options.as_json` to get a ruby hash with a JSON representation if needed.

# If inside a Rails controller, `render json: request_options` will just work.
# I.e. it will encode and convert the options to JSON automatically.
```

#### `WebAuthn::Credential.from_create(credential_create_result)`

```ruby
credential_with_attestation = WebAuthn::Credential.from_create(params[:publicKeyCredential])
```

#### `WebAuthn::Credential.from_get(credential_get_result)`

```ruby
credential_with_assertion = WebAuthn::Credential.from_get(params[:publicKeyCredential])
```

#### `PublicKeyCredentialWithAttestation#verify(challenge)`

Verifies the created WebAuthn credential is [valid](https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential).

```ruby
credential_with_attestation.verify(session[:creation_challenge])
```

#### `PublicKeyCredentialWithAssertion#verify(challenge, public_key:, sign_count:)`

Verifies the asserted WebAuthn credential is [valid](https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion).

Mainly, that the client provided a valid cryptographic signature for the corresponding stored credential public
key, among other extra validations.

```ruby
credential_with_assertion.verify(
  session[:authentication_challenge],
  public_key: stored_credential.public_key,
  sign_count: stored_credential.sign_count
)
```

#### `PublicKeyCredential#client_extension_outputs`

```ruby
credential = WebAuthn::Credential.from_create(params[:publicKeyCredential])

credential.client_extension_outputs
```

#### `PublicKeyCredential#authenticator_extension_outputs`

```ruby
credential = WebAuthn::Credential.from_create(params[:publicKeyCredential])

credential.authenticator_extension_outputs
```

## Attestation

### Attestation Statement Formats

| Attestation Statement Format | Supported? |
| -------- | :--------: |
| packed (self attestation) | Yes |
| packed (x5c attestation) | Yes |
| tpm (x5c attestation) | Yes |
| android-key | Yes |
| android-safetynet | Yes |
| apple | Yes |
| fido-u2f | Yes |
| none | Yes |

### Attestation Types

You can define what trust policy to enforce by setting `acceptable_attestation_types` config to a subset of `['None', 'Self', 'Basic', 'AttCA', 'Basic_or_AttCA']` and `attestation_root_certificates_finders` to an object that responds to `#find` and returns the corresponding root certificate for each registration. The `#find` method will be called passing keyword arguments `attestation_format`, `aaguid` and `attestation_certificate_key_id`.

## Testing Your Integration

The Webauthn spec requires for data that is signed and authenticated. As a result, it can be difficult to create valid test authenticator data when testing your integration. webauthn-ruby exposes [WebAuthn::FakeClient](https://github.com/cedarcode/webauthn-ruby/blob/master/lib/webauthn/fake_client.rb) for you to use in your tests. Example usage can be found in [webauthn-ruby/spec/webauthn/authenticator_assertion_response_spec.rb](https://github.com/cedarcode/webauthn-ruby/blob/master/spec/webauthn/authenticator_assertion_response_spec.rb).

## Contributing

See [the contributing file](CONTRIBUTING.md)!

Bug reports, feature suggestions, and pull requests are welcome on GitHub at https://github.com/cedarcode/webauthn-ruby.

## License

The library is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
