# frozen_string_literal: true

require "webauthn/authenticator_data"
require "webauthn/authenticator_response"
require "webauthn/encoder"
require "webauthn/public_key"

module WebAuthn
  class SignatureVerificationError < VerificationError; end
  class SignCountVerificationError < VerificationError; end

  class AuthenticatorAssertionResponse < AuthenticatorResponse
    def self.from_client(response, relying_party: WebAuthn.configuration.relying_party)
      encoder = relying_party.encoder

      user_handle =
        if response["userHandle"]
          encoder.decode(response["userHandle"])
        end

      new(
        authenticator_data: encoder.decode(response["authenticatorData"]),
        client_data_json: encoder.decode(response["clientDataJSON"]),
        signature: encoder.decode(response["signature"]),
        user_handle: user_handle,
        relying_party: relying_party
      )
    end

    attr_reader :user_handle

    def initialize(authenticator_data:, signature:, user_handle: nil, **options)
      super(**options)

      @authenticator_data_bytes = authenticator_data
      @signature = signature
      @user_handle = user_handle
    end

    def verify(expected_challenge, expected_origin = nil, public_key:, sign_count:, user_verification: nil, rp_id: nil)
      super(expected_challenge, expected_origin, user_verification: user_verification, rp_id: rp_id)
      verify_item(:signature, WebAuthn::PublicKey.deserialize(public_key))
      verify_item(:sign_count, sign_count)

      true
    end

    def authenticator_data
      @authenticator_data ||= WebAuthn::AuthenticatorData.deserialize(authenticator_data_bytes)
    end

    private

    attr_reader :authenticator_data_bytes, :signature

    def valid_signature?(webauthn_public_key)
      webauthn_public_key.verify(signature, authenticator_data_bytes + client_data.hash)
    end

    def valid_sign_count?(stored_sign_count)
      normalized_sign_count = stored_sign_count || 0
      if authenticator_data.sign_count.nonzero? || normalized_sign_count.nonzero?
        authenticator_data.sign_count > normalized_sign_count
      else
        true
      end
    end

    def type
      WebAuthn::TYPES[:get]
    end
  end
end
