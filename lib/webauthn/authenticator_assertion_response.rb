# frozen_string_literal: true

require "webauthn/authenticator_response"

module WebAuthn
  class AuthenticatorAssertionResponse < AuthenticatorResponse
    def initialize(authenticator_data:, signature:, **options)
      super(options)

      @authenticator_data_bytes = authenticator_data
      @signature = signature
    end

    def valid?(original_challenge, original_origin, credential_public_key:)
      valid_type? &&
        valid_challenge?(original_challenge) &&
        valid_origin?(original_origin) &&
        authenticator_data.user_present? &&
        valid_signature?(credential_public_key)
    end

    private

    attr_reader :authenticator_data_bytes, :signature

    def valid_signature?(public_key_bytes)
      group = OpenSSL::PKey::EC::Group.new("prime256v1")
      key = OpenSSL::PKey::EC.new(group)
      public_key_bn = OpenSSL::BN.new(public_key_bytes, 2)
      public_key = OpenSSL::PKey::EC::Point.new(group, public_key_bn)
      key.public_key = public_key

      key.verify(
        "SHA256",
        signature,
        authenticator_data_bytes + client_data.hash
      )
    end

    def authenticator_data
      @authenticator_data ||= WebAuthn::AuthenticatorData.new(authenticator_data_bytes)
    end

    def type
      WebAuthn::TYPES[:get]
    end
  end
end
