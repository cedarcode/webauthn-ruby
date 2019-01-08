# frozen_string_literal: true

module WebAuthn
  # Generic WebAuthn exception class
  class Error < StandardError; end

  class ClientDataMissing < Error
    def initialize
      super("Client Data JSON is missing")
    end
  end
end
