# frozen_string_literal: true

require "webauthn/authenticator_attestation_response"
require "webauthn/public_key_credential"

module WebAuthn
  class PublicKeyCredentialWithAttestation < PublicKeyCredential
    def self.response_class
      WebAuthn::AuthenticatorAttestationResponse
    end

    def verify(challenge, expected_origin: nil, **keywords)
      super

      response.verify(encoder.decode(challenge), expected_origin, **keywords)

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
