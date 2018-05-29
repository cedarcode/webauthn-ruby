# frozen_string_literal: true

module WebAuthn
  module Utils
    def self.ua_encode(bin)
      Base64.strict_encode64(bin)
    end

    def self.ua_decode(str)
      Base64.strict_decode64(str)
    end

    def self.authenticator_decode(str)
      Base64.urlsafe_decode64(str)
    end
  end
end
