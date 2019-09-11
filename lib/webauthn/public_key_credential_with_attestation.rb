# frozen_string_literal: true

require "webauthn/authenticator_attestation_response"
require "webauthn/encoder"
require "webauthn/public_key_credential"

module WebAuthn
  class PublicKeyCredentialWithAttestation < PublicKeyCredential
    def self.from_client(credential)
      encoder = WebAuthn.configuration.encoder

      new(
        type: credential["type"],
        id: credential["id"],
        raw_id: encoder.decode(credential["rawId"]),
        response: WebAuthn::AuthenticatorAttestationResponse.new(
          attestation_object: encoder.decode(credential["response"]["attestationObject"]),
          client_data_json: encoder.decode(credential["response"]["clientDataJSON"])
        )
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
