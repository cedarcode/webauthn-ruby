# frozen_string_literal: true

require "webauthn/authenticator_attestation_response"
require "webauthn/public_key_credential"

module WebAuthn
  class PublicKeyCredentialWithAttestation < PublicKeyCredential
    def self.response_class
      WebAuthn::AuthenticatorAttestationResponse
    end

    def verify(challenge, user_verification: nil)
      super

      response.verify(encoder.decode(challenge), user_verification: user_verification)

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
