# frozen_string_literal: true

require "webauthn/authenticator_assertion_response"
require "webauthn/encoder"
require "webauthn/public_key_credential"

module WebAuthn
  class PublicKeyCredentialWithAssertion < PublicKeyCredential
    def self.response_from_client(response)
      encoder = WebAuthn.configuration.encoder

      user_handle =
        if response["userHandle"]
          encoder.decode(response["userHandle"])
        end

      WebAuthn::AuthenticatorAssertionResponse.new(
        authenticator_data: encoder.decode(response["authenticatorData"]),
        client_data_json: encoder.decode(response["clientDataJSON"]),
        signature: encoder.decode(response["signature"]),
        user_handle: user_handle
      )
    end

    def verify(challenge, public_key:, sign_count:)
      super

      response.verify(encoder.decode(challenge), public_key: encoder.decode(public_key), sign_count: sign_count)

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
