# frozen_string_literal: true

require "webauthn/authenticator_response"

module WebAuthn
  class AuthenticatorAssertionResponse < AuthenticatorResponse
    def initialize(authenticator_data:, **options)
      super(options)

      @authenticator_data_bytes = authenticator_data
    end

    def valid?(original_challenge, original_origin)
      valid_type? &&
        valid_challenge?(original_challenge) &&
        valid_origin?(original_origin) &&
        authenticator_data.user_present?
    end

    private

    attr_reader :authenticator_data_bytes

    def authenticator_data
      @authenticator_data ||= WebAuthn::AuthenticatorData.new(authenticator_data_bytes)
    end

    def type
      WebAuthn::TYPES[:get]
    end
  end
end
