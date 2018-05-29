# frozen_string_literal: true

require "webauthn/authenticator_response"

module WebAuthn
  class AuthenticatorAssertionResponse < AuthenticatorResponse
    def valid?
      client_data.type == WebAuthn::TYPES[:get]
    end
  end
end
