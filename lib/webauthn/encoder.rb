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
        [data].pack("m0") # Base64.strict_encode64(data)
      when :base64url
        data = [data].pack("m0") # Base64.urlsafe_encode64(data, padding: false)
        data.chomp!("==") or data.chomp!("=")
        data.tr!("+/", "-_")
        data
      when nil, false
        data
      else
        raise "Unsupported or unknown encoding: #{encoding}"
      end
    end

    def decode(data)
      case encoding
      when :base64
        data.unpack1("m0") # Base64.strict_decode64(data)
      when :base64url
        if !data.end_with?("=") && data.length % 4 != 0 #  Base64.urlsafe_decode64(data)
          data = data.ljust((data.length + 3) & ~3, "=")
          data.tr!("-_", "+/")
        else
          data = data.tr("-_", "+/")
        end
        data.unpack1("m0")
      when nil, false
        data
      else
        raise "Unsupported or unknown encoding: #{encoding}"
      end
    end
  end
end
