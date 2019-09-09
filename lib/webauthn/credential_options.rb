# frozen_string_literal: true

require "securerandom"

module WebAuthn
  class CredentialOptions
    CHALLENGE_LENGTH = 32

    def challenge
      @challenge ||= SecureRandom.random_bytes(CHALLENGE_LENGTH)
    end

    def timeout
      @timeout = WebAuthn.configuration.credential_options_timeout
    end
  end
end
