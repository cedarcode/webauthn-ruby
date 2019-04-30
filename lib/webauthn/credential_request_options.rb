# frozen_string_literal: true

require "webauthn/credential_options"

module WebAuthn
  class CredentialRequestOptions < CredentialOptions
    def to_h
      { challenge: challenge, allowCredentials: allow_credentials }
    end

    def allow_credentials
      []
    end
  end
end
