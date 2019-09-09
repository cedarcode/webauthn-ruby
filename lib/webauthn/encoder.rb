# frozen_string_literal: true

require "base64"
require "webauthn/configuration"

module WebAuthn
  class Encoder
    attr_reader :encoding

    def initialize(encoding = WebAuthn.configuration.encoding)
      @encoding = encoding
    end

    def encode(data)
      case encoding
      when :base64
        Base64.strict_encode64(data)
      when :base64url
        Base64.urlsafe_encode64(data, padding: false)
      when nil, false
        data
      else
        raise "Unsupported or unknown encoding: #{encoding}"
      end
    end

    def decode(data)
      case encoding
      when :base64
        Base64.strict_decode64(data)
      when :base64url
        Base64.urlsafe_decode64(data)
      when nil, false
        data
      else
        raise "Unsupported or unknown encoding: #{encoding}"
      end
    end
  end
end
