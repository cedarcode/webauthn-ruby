# Attestation

The gem supports verifying the authenticator attestation, an advanced feature that allows your application to check the provenance, features and security status of an authenticator.
See [FIDO TechNotes: The Truth about Attestation](https://fidoalliance.org/fido-technotes-the-truth-about-attestation/) for a generic overview. 

Consumer use cases generally do not require attestation, like you would not care for which type of phone your user receives SMS codes with/generates TOTP codes on.
If you decide you may need attestation, continue on reading to understand the work and tradeoffs involved. 

## FIDO Metadata Service (MDS)

You will need a token to use the FIDO Metadata Service, which can be obtained after registration at https://mds2.fidoalliance.org/tokens/

You can configure the gem as such:

```ruby
WebAuthn.configure do |config|
  config.verify_attestation_statement = true
  config.metadata_token = "your token"
end
```

## Integrating the cache backend

The gem uses a caching abstraction you need to implement in your application for performance and resiliency. The interface is inspired by Rails' `ActiveSupport::Cache`.
This allows you to use any datastore you like, and using different strategies to keep data fresh such as just-in-time retrieval or a daily job.

The interface you need to implement is as follows:

```ruby
class FidoMetadataCacheStore
  def read(name, _options = nil)
    # return `value`
  end

  def write(name, value, _options = nil)
    # store `value` so it can be looked up using `name`
  end
end
```

Configure the gem to use it:
```ruby
WebAuthn.configure do |config|
  config.cache_backend = FidoMetadataCacheStore.new
end
```

If you want to use the daily job strategy, look at how the gem uses the `WebAuthn::Metadata::Client` class internally.

## Integration in your registration and authentication flows

The gem supports 'direct' attestation, also known as 'batch attestation' in FIDO parleance.

Some notes about the implementation of different attestation formats:
- U2F and packed formats use the FIDO Metadata Service to look up authenticator metadata which includes root certificates. Without metadata verification fails.
- Android Safetynet and Android Keystore formats attempt lookup in the MDS, if no metadata is found bundled Google certificates are used.
- TPM format attempts lookup in the MDS, if no metadata is found bundled Trusted Computing Group certificates from Microsoft are used.

This means that depending on your risk profile, you need to decide how to handle:
- Successful attestation verification with metadata present means you will need to interpret the metadata: 
  - `metadata_entry` among other things contains an array of `status_reports` which indicate the authenticator security status.
  - `metadata_statement` describes detailed characteristics about the authenticator, such as the accuracy of user verification (PIN, biometrics) employed
- Successful attestation verification without metadata present
- Failed attestation verification (`AttestationStatementVerificationError` is raised)

During registration you should store the AAGUID (or attestation key identifier) alongside other authenticator data:

```ruby
begin
  attestation_response.verify(expected_challenge)

  if (entry = attestation_response.metadata_entry)
    # If a MetadataTOCPayloadEntry is found, you'll want to verify if `entry.status_reports.last.status` is acceptable
    # A list if possible values can be found at
    # https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-service-v2.0-rd-20180702.html#authenticatorstatus-enum
 
    # You can also find the MetadataStatement by invoking `attestation_response.metadata_statement`
    # For a description of it's contents see 
    # https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html
  else
    # Decide how to handle successful attestation verification without metadata
  end

  # For future reference, alongside the credential ID and public key (as described in the README) also store:
  # - `attestation_response.aaguid` for CTAP2 devices, or if that is nil
  # - `attestation_response.attestation_certificate_key_id` for CTAP1 (U2F) devices
rescue WebAuthn::VerificationError => e
  # Handle error
end
```

It is possible that an authenticator was discovered to be compromised after registration in your application.
During authentication or a periodic job you can use the AAGUID (or attestation key identifier) to see if the authenticator is still considered secure.

```ruby
begin
  assertion_response.verify(expected_challenge, public_key: credential.public_key, sign_count: credential.sign_count)

  if (entry = WebAuthn::Metadata::Store.fetch_entry(aaguid: credential.aaguid))
    # Use similar logic as in the registration example to determine acceptable status
    # You can also use `WebAuthn::Metadata::Store.fetch_statement` to retrieve the metadata_statement
  else
    # Decide how to handle registered authenticators without metadata
  end

  # If authenticator is still acceptable, update the stored credential sign count and sign in the user (as described in the README)
rescue WebAuthn::VerificationError => e
  # Handle error
end
```
