# frozen_string_literal: true

module WebAuthn
  # Generic WebAuthn exception class
  class WebAuthnError < StandardError; end

  class ClientDataMissing < WebAuthnError
    def initialize
      super("Client Data JSON is missing")
    end
  end
end
