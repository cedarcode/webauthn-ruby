# frozen_string_literal: true

require "webauthn/credential_options"

module WebAuthn
  def self.credential_request_options
    CredentialRequestOptions.new.to_h
  end

  class CredentialRequestOptions < CredentialOptions
    attr_accessor :allow_credentials, :extensions

    def initialize(allow_credentials: [], extensions: nil)
      @allow_credentials = allow_credentials
      @extensions = extensions
    end

    def to_h
      options = { challenge: challenge, allowCredentials: allow_credentials }

      if extensions
        options[:extensions] = extensions
      end

      options
    end
  end
end
