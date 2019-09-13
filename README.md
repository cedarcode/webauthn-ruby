__Note__: You are viewing the README for the development version of webauthn-ruby.
For the current release version see https://github.com/cedarcode/webauthn-ruby/blob/1-stable/README.md.

# webauthn-ruby

![banner](webauthn-ruby.png)

[![Gem](https://img.shields.io/gem/v/webauthn.svg?style=flat-square)](https://rubygems.org/gems/webauthn)
[![Travis](https://img.shields.io/travis/cedarcode/webauthn-ruby/master.svg?style=flat-square)](https://travis-ci.org/cedarcode/webauthn-ruby)
[![Conventional Commits](https://img.shields.io/badge/Conventional%20Commits-1.0.0-informational.svg?style=flat-square)](https://conventionalcommits.org)
[![Join the chat at https://gitter.im/cedarcode/webauthn-ruby](https://badges.gitter.im/cedarcode/webauthn-ruby.svg)](https://gitter.im/cedarcode/webauthn-ruby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

> WebAuthn ruby server library

Makes your Ruby/Rails web server become a functional [WebAuthn Relying Party](https://www.w3.org/TR/webauthn/#webauthn-relying-party).

Takes care of the [server-side operations](https://www.w3.org/TR/webauthn/#rp-operations) needed to
[register](https://www.w3.org/TR/webauthn/#registration) or [authenticate](https://www.w3.org/TR/webauthn/#authentication)
a user [credential](https://www.w3.org/TR/webauthn/#public-key-credential), including the necessary cryptographic checks.

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
- How to use [WebAuthn in Android apps](https://developers.google.com/identity/fido/android/native-apps)
- [Security Benefits for WebAuthn Servers (a.k.a Relying Parties)](https://www.w3.org/TR/webauthn/#sctn-rp-benefits)

## Prerequisites

This ruby library will help your Ruby/Rails server act as a conforming [_Relying-Party_](https://www.w3.org/TR/webauthn/#relying-party), in WebAuthn terminology. But for the [_Registration_](https://www.w3.org/TR/webauthn/#registration) and [_Authentication_](https://www.w3.org/TR/webauthn/#authentication) ceremonies to fully work, you will also need to add two more pieces to the puzzle, a conforming [User Agent](https://www.w3.org/TR/webauthn/#conforming-user-agents) + [Authenticator](https://www.w3.org/TR/webauthn/#conforming-authenticators) pair.

Known conformant pairs are, for example:

- Google Chrome for Android 70+ and Android's Fingerprint-based platform authenticator
- Microsoft Edge and Windows 10 platform authenticator
- Mozilla Firefox for Desktop and Yubico's Security Key roaming authenticator via USB

For a detailed picture about what is conformant and what not, you can refer to:

- [apowers313/fido2-webauthn-status](https://github.com/apowers313/fido2-webauthn-status)
- [FIDO certified products](https://fidoalliance.org/certification/fido-certified-products)


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

You can find a working example on how to use this gem in a __Rails__ app in [webauthn-rails-demo-app](https://github.com/cedarcode/webauthn-rails-demo-app).

If you are migrating an existing application from the legacy FIDO U2F JavaScript API to WebAuthn, also refer to
[`docs/u2f_migration.md`](docs/u2f_migration.md).

### Configuration

For a Rails application this would go in `config/initializers/webauthn.rb`.

```ruby
WebAuthn.configure do |config|
  # This value needs to match `window.location.origin` evaluated by
  # the User Agent during registration and authentication ceremonies.
  config.origin = "https://auth.example.com"

  # Relying Party name for display purposes
  config.rp_name = "Example Inc."

  # Optionally configure a client timeout hint, in milliseconds.
  # This hint specifies how long the browser should wait for an
  # attestation or an assertion response.
  # This hint may be overridden by the browser.
  # https://www.w3.org/TR/webauthn/#dom-publickeycredentialcreationoptions-timeout
  config.credential_options_timeout = 120000

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
  # config.encoding = false
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

create_options = WebAuthn::Credential.create_options(
  user: { id: user.webauthn_id, name: user.name }
  exclude: user.credentials.map { |c| c.webauthn_id }
)

# Store the newly generated challenge somewhere so you can have it
# for the verification phase.
session[:creation_challenge] = create_options.challenge

# Send `create_options` back to the browser, so that they can be used
# to call `navigator.credentials.create({ "publicKey": createOptions })`
#
# You can call `create_options.as_json` to get a ruby hash with a JSON representation if needed.

# If inside a Rails controller, `render json: create_options` will just work.
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
get_options = WebAuthn::Credential.get_options(allow: user.credentials.map { |c| c.webauthn_id })

# Store the newly generated challenge somewhere so you can have it
# for the verification phase.
session[:authentication_challenge] = get_options.challenge

# Send `get_options` back to the browser, so that they can be used
# to call `navigator.credentials.get({ "publicKey": getOptions })`

# You can call `get_options.as_json` to get a ruby hash with a JSON representation if needed.

# If inside a Rails controller, `render json: get_options` will just work.
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

## API

_Pending_

## Attestation Statement Formats

| Attestation Statement Format | Supported? |
| -------- | :--------: |
| packed (self attestation) | Yes |
| packed (x5c attestation) | Yes |
| packed (ECDAA attestation) | No |
| tpm (x5c attestation) | Yes |
| tpm (ECDAA attestation) | No |
| android-key | Yes |
| android-safetynet | Yes |
| fido-u2f | Yes |
| none | Yes |

NOTE: Be aware that it is up to you to do "trust path validation" (steps 15 and 16 in [Registering a new credential](https://www.w3.org/TR/webauthn/#registering-a-new-credential)) if that's a requirement of your Relying Party policy. The gem doesn't perform that validation for you right now.

## Testing Your Integration

The Webauthn spec requires for data that is signed and authenticated. As a result, it can be difficult to create valid test authenticator data when testing your integration. webauthn-ruby exposes [WebAuthn::FakeClient](https://github.com/cedarcode/webauthn-ruby/blob/master/lib/webauthn/fake_client.rb) for you to use in your tests. Example usage can be found in [webauthn-ruby/spec/webauthn/authenticator_assertion_response_spec.rb](https://github.com/cedarcode/webauthn-ruby/blob/master/spec/webauthn/authenticator_assertion_response_spec.rb).

## Contributing

See [the contributing file](CONTRIBUTING.md)!

Bug reports, feature suggestions, and pull requests are welcome on GitHub at https://github.com/cedarcode/webauthn-ruby.

## License

The library is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
