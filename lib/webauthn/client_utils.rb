# frozen_string_literal: true

require "base64"

module WebAuthn
  module ClientUtils
    def self.encode(data)
      # TODO: Make this configurable so users can choose to use regular Base64
      # in the front-end instead of being forced to use URL-safe Base64
      Base64.urlsafe_encode64(data, padding: false)
    end

    def self.decode(data)
      # TODO: Make this configurable so users can choose to use regular Base64
      # in the front-end instead of being forced to use URL-safe Base64
      Base64.urlsafe_decode64(data)
    end
  end
end
