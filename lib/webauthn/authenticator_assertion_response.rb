# frozen_string_literal: true

require "webauthn/authenticator_response"

module WebAuthn
  class AuthenticatorAssertionResponse < AuthenticatorResponse
    def initialize(credential_id:, authenticator_data:, signature:, **options)
      super(options)

      @credential_id = credential_id
      @authenticator_data_bytes = authenticator_data
      @signature = signature
    end

    def valid?(original_challenge, original_origin, allowed_credential:)
      super(original_challenge, original_origin) &&
        valid_credential?(allowed_credential.id) &&
        valid_signature?(allowed_credential.public_key)
    end

    private

    attr_reader :credential_id, :authenticator_data_bytes, :signature

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

    def valid_credential?(allowed_credential_id)
      allowed_credential_id == credential_id
    end

    def authenticator_data
      @authenticator_data ||= WebAuthn::AuthenticatorData.new(authenticator_data_bytes)
    end

    def type
      WebAuthn::TYPES[:get]
    end
  end
end
