# frozen_string_literal: true
require 'base64url'

module WebAuthn
  module Utils
    def self.authenticator_decode(str)
      Base64URL.decode(str)
    end
  end
end
