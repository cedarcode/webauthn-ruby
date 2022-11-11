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
        user_verification: user_verification,
        rp_id: appid_extension_output ? appid : nil
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

    private

    def appid_extension_output
      return if client_extension_outputs.nil?

      client_extension_outputs['appid']
    end

    def appid
      URI.parse(relying_party.legacy_u2f_appid || raise("Unspecified legacy U2F AppID")).to_s
    end
  end
end
