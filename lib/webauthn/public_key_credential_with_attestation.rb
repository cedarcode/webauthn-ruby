# frozen_string_literal: true

require "webauthn/authenticator_attestation_response"
require "webauthn/encoder"
require "webauthn/public_key_credential"

module WebAuthn
  class PublicKeyCredentialWithAttestation < PublicKeyCredential
    def self.response_from_client(response)
      encoder = WebAuthn.configuration.encoder

      WebAuthn::AuthenticatorAttestationResponse.new(
        attestation_object: encoder.decode(response["attestationObject"]),
        client_data_json: encoder.decode(response["clientDataJSON"])
      )
    end

    def verify(challenge)
      super

      response.verify(encoder.decode(challenge))

      true
    end

    def public_key
      if raw_public_key
        encoder.encode(raw_public_key)
      end
    end

    def raw_public_key
      response&.authenticator_data&.credential&.public_key
    end
  end
end
