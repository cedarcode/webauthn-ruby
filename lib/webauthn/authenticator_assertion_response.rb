# frozen_string_literal: true

require "webauthn/authenticator_response"

module WebAuthn
  class AuthenticatorAssertionResponse < AuthenticatorResponse
    def initialize(authenticator_data:, **options)
      super(options)

      @authenticator_data_bytes = authenticator_data
    end

    def valid?
      client_data.type == WebAuthn::TYPES[:get] &&
        authenticator_data.user_present?
    end

    private

    attr_reader :authenticator_data_bytes

    def authenticator_data
      @authenticator_data ||= WebAuthn::AuthenticatorData.new(authenticator_data_bytes)
    end
  end
end
