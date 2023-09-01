# Advanced Configuration

## Global vs Instance Based Configuration

Which approach suits best your needs will depend on the architecture of your application and how do your users need to register and authenticate to it.

If you have a multi-tenant application, or any application segmenation, where your users register and authenticate to each of these tenants or segments individuallly using different hostnames, or with different security needs, you need to go through [Instance Based Configuration](#instance-based-configuration).

However, if your application is served for just one hostname, or else if your users authenticate to only one subdmain (e.g. your application serves www.example.com and admin.example.com but all you users authenticate through auth.example.com) you can still rely on one [Global Configuration](../README.md#configuration).

If you are still not sure, or want to keep your options open, be aware that [Instance Based Configuration](#instance-based-configuration) is also a valid way of defining a single instance configuration and how you share such configuration across your application, it's up to you.


## Instance Based Configuration

Intead of the [Global Configuration](../README.md#configuration) you place in `config/initializers/webauthn.rb`,
 you can now have an on-demand instance of `WebAuthn::RelyingParty` with the same configuration options, that
 you can build anywhere in you application, in the following way:

```ruby
  relying_party = WebAuthn::RelyingParty.new(
    # This value needs to match `window.location.origin` evaluated by
    # the User Agent during registration and authentication ceremonies.
    origin: "https://admin.example.com",

    # Relying Party name for display purposes
    name: "Admin Site for Example Inc."

    # Optionally configure a client timeout hint, in milliseconds.
    # This hint specifies how long the browser should wait for any
    # interaction with the user.
    # This hint may be overridden by the browser.
    # https://www.w3.org/TR/webauthn/#dom-publickeycredentialcreationoptions-timeout
    # credential_options_timeout: 120_000

    # You can optionally specify a different Relying Party ID
    # (https://www.w3.org/TR/webauthn/#relying-party-identifier)
    # if it differs from the default one.
    #
    # In this case the default would be "admin.example.com", but you can set it to
    # the suffix "example.com"
    #
    # id: "example.com"

    # Configure preferred binary-to-text encoding scheme. This should match the encoding scheme
    # used in your client-side (user agent) code before sending the credential to the server.
    # Supported values: `:base64url` (default), `:base64` or `false` to disable all encoding.
    #
    # encoding: :base64url

    # Possible values: "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512", "RS1"
    # Default: ["ES256", "PS256", "RS256"]
    #
    # algorithms: ["ES384"]
  )
```

## Instance Based API

**DISCLAIMER: This API was released on version 3.0.0.alpha1 and is still under evaluation. Although it has been throughly tested and it is fully functional it might be changed until the final release of version 3.0.0.**

The explanation for each ceremony can be found in depth in [Credential Registration](../README.md#credential-registration) and [Credential Authentication](../README.md#credential-authentication) but if you choose this instance based approach to define your WebAuthn configurations and assuming `relying_party` is the result of an instance you get through `WebAuthn::RelyingParty.new(...)` the code in those explanations needs to be updated to:

### Credential Registration

#### Initiation phase

```ruby
# Generate and store the WebAuthn User ID the first time the user registers a credential
if !user.webauthn_id
  user.update!(webauthn_id: WebAuthn.generate_user_id)
end

options = relying_party.options_for_registration(
  user: { id: user.webauthn_id, name: user.name },
  exclude: user.credentials.map { |c| c.external_id }
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
begin
  webauthn_credential = relying_party.verify_registration(
    params[:publicKeyCredential],
    params[:create_challenge]
  )

  # Store Credential ID, Credential Public Key and Sign Count for future authentications
  user.credentials.create!(
    external_id: webauthn_credential.id,
    public_key: webauthn_credential.public_key,
    sign_count: webauthn_credential.sign_count
  )
rescue WebAuthn::Error => e
  # Handle error
end
```

### Credential Authentication

#### Initiation phase

```ruby
options = relying_party.options_for_authentication(allow: user.credentials.map { |c| c.webauthn_id })

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

```ruby
begin
  # Assuming you're using @github/webauthn-json package to send the `PublicKeyCredential` object back
  # in params[:publicKeyCredential]:
  webauthn_credential, stored_credential = relying_party.verify_authentication(
    params[:publicKeyCredential],
    session[:authentication_challenge]
  ) do |webauthn_credential|
    # the returned object needs to respond to #public_key and #sign_count
    user.credentials.find_by(external_id: webauthn_credential.id)
  end

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

## Moving from Global to Instance Based Configuration

Adding a configuration for a new instance does not mean you need to get rid of your Global configuration. They can co-exist in your application and be both available for the different usages you might have. `WebAuthn.configuration.relying_party` will always return the global one while `WebAuthn::RelyingParty.new`, executed anywhere in your codebase, will allow you to create a different instance as you see the need. They will not collide and instead operate in isolation without any shared state.

The gem API described in the current [Usage](../README.md#usage) section for the [Global Configuration](../README.md#configuration) approach will still valid but the [Instance Based API](#instance-based-api) also works with the global `relying_party` that is maintain globally at `WebAuthn.configuration.relying_party`.
