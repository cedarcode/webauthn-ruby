# Migrating from U2F to WebAuthn

The Chromium team [recommends](https://groups.google.com/a/chromium.org/forum/#!msg/security-dev/BGWA1d7a6rI/W2avestmBAAJ)
application developers to switch from the U2F API to the WebAuthn API. This document describes how a Ruby application
using the [u2f gem by Castle](https://github.com/castle/ruby-u2f) can migrate existing credentials so that their users
do not experience interruption or need to re-register their security keys.

Note that the migration is one-way: credentials registered using WebAuthn cannot be made compatible with the U2F API.
It is recommended to successfully migrate authorization flows before migrating registration flows.

## Migrate registered U2F credentials

Assuming you have a registered credential per the u2f gem readme, base64 urlsafe encoded in a database:

```ruby
# This domain will be used in all code examples. It's a single-facet app but a multi-facet AppID
# (e.g. https://example.com/app-id.json) will work as well.
domain = URI("https://login.example.com")

u2f_registration = U2F::U2F.new(domain.to_s).register!(u2f_challenge, u2f_register_response)
# => #<U2F::Registration:0x00007fd62f43d688
#  @certificate=
#   "MIIBCzCBsgIBATAKBggqhkjOPQQDAjASMRAwDgYDVQQDDAdVMkZUZXN0MB4XDTE5MDUzMDE3MjIwM1oXDTIwMDUyOTE3MjIwM1owEjEQMA4GA1UEAwwHVTJGVGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBMKpejumzlH6NxWIx2Ol+EManS9oX5nguG4RT43rZNkyn/zGjdJEhXksN5zT34rLZgFheBgkDGJCdtTPlhVK10wCgYIKoZIzj0EAwIDSAAwRQIhALYxFcROCeifWpv5+wNZIiaO/bGQg8rFBHCw3aHgehdZAiBJ3xFmQh7+Gjxt6CeAcY/k/VVAYu2vP4sUqXnCQFgJUA==",
#  @key_handle="mbVMRTgzST5xLumckGztJ9VFW6veObfNIYWSn3sTqIY",
#  @public_key="BOJQXlFg+ZfZKm48FNq2Ye5vSwOscE1i7YsGRSIjIe3GI0OXrSBDADDn0dQlz2iDzZ7LvCwiHz72U1qhVas3vus=">
```

The `U2fMigrator` class quacks like `WebAuthn::AuthenticatorAttestationResponse` and can be used similarly as documented
in the [registration verification phase](https://github.com/cedarcode/webauthn-ruby/blob/master/README.md#verification-phase).
Of course a `verify` instance method is not implemented, as there is no real interaction with an authenticator.

The migrator can be used to convert credentials in real time during authentication while keeping them stored in the U2F
format, and in a backfill task to store credentials in the new format, depending on how you are approaching your
migration.

```ruby
require "webauthn/u2f_migrator"

migrated_credential = WebAuthn::U2fMigrator.new(
  app_id: domain,
  certificate: u2f_registration.certificate,
  key_handle: u2f_registration.key_handle,
  public_key: u2f_registration.public_key,
  counter: u2f_registration.counter
)
migrated_credential.credential.id
# => "\x99\xB5LE83I>q.\xE9\x9C\x90l\xED'\xD5E[\xAB\xDE9\xB7\xCD!\x85\x92\x9F{\x13\xA8\x86"
migrated_credential.credential.public_key
# => "\xA5\x03& \x01!X \xE2P^Q`\xF9\x97\xD9*n<\x14\xDA\xB6a\xEEoK\x03\xACpMb\xED\x8B\x06E\"#!\xED\xC6\x01\x02\"X #C\x97\xAD C\x000\xE7\xD1\xD4%\xCFh\x83\xCD\x9E\xCB\xBC,\"\x1F>\xF6SZ\xA1U\xAB7\xBE\xEB"
migrated_credential.authenticator_data.sign_count
# => 41
```

## Authenticate migrated U2F credentials

Following the documentation on the [authentication initiation](https://github.com/cedarcode/webauthn-ruby/blob/master/README.md#initiation-phase-1),
you need to specify the [FIDO AppID extension](https://www.w3.org/TR/webauthn/#sctn-appid-extension) for U2F migratedq
credentials. The WebAuthn standard explains:

> The FIDO APIs use an alternative identifier for Relying Parties called an _AppID_, and any credentials created using
> those APIs will be scoped to that identifier. Without this extension, they would need to be re-registered in order to
> be scoped to an RP ID.

For the earlier given example `domain` this means:
- FIDO AppID: `https://login.example.com`
- Valid RP IDs: `login.example.com` (default) and `example.com`

You can request the use of the `appid` extension by setting the AppID in the configuration, like this:

```ruby
WebAuthn.configure do |config|
  config.legacy_u2f_appid = "https://login.example.com"
end
```

By doing this, the `appid` extension will be automatically requested when generating the options for get:

```ruby
options = WebAuthn::Credential.options_for_get
```

On the frontend, in the resolved value from `navigator.credentials.get({ "publicKey": credentialRequestOptions })` add
a call to [getClientExtensionResults()](https://www.w3.org/TR/webauthn/#dom-publickeycredential-getclientextensionresults)
and send its result to your backend alongside the `id`/`rawId` and `response` values. If the authenticator used the AppID
extension, the returned value will contain `{ "appid": true }`.

During authentication verification phase, if you followed the [verification phase documentation](https://github.com/cedarcode/webauthn-ruby#verification-phase-1) and have set the AppID in the config, the method `PublicKeyCredentialWithAssertion#verify` will be smart enough to determine if it should use the AppID or the RP ID to verify the WebAuthn credential, depending on the output of the `appid` client extension:

> If true, the AppID was used and thus, when verifying an assertion, the Relying Party MUST expect the `rpIdHash` to be
> the hash of the _AppID_, not the RP ID.
