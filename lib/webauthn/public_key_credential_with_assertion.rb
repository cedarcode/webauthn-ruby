# frozen_string_literal: true

require "webauthn/authenticator_assertion_response"
require "webauthn/public_key_credential"

module WebAuthn
  class PublicKeyCredentialWithAssertion < PublicKeyCredential
    def self.response_class
      WebAuthn::AuthenticatorAssertionResponse
    end

    def verify(challenge, public_key:, sign_count:, user_verification: nil)
      super

      response.verify(
        encoder.decode(challenge),
        public_key: encoder.decode(public_key),
        sign_count: sign_count,
        user_verification: user_verification
      )

      true
    end

    def user_handle
      if raw_user_handle
        encoder.encode(raw_user_handle)
      end
    end

    def raw_user_handle
      response.user_handle
    end
  end
end
