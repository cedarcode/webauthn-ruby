# frozen_string_literal: true

require "base64"

module WebAuthn
  def self.standard_encoder
    @standard_encoder ||= Encoder.new
  end

  class Encoder
    # https://www.w3.org/TR/webauthn-2/#base64url-encoding
    STANDARD_ENCODING = :base64url

    attr_reader :encoding

    def initialize(encoding = STANDARD_ENCODING)
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
