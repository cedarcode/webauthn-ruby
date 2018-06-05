# frozen_string_literal: true

module WebAuthn
  module Utils
    def self.authenticator_decode(str)
      Base64.urlsafe_decode64(str)
    end
  end
end
