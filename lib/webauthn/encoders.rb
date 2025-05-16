# frozen_string_literal: true

module WebAuthn
  def self.standard_encoder
    @standard_encoder ||= Encoders.lookup(Encoders::STANDARD_ENCODING)
  end

  module Encoders
    # https://www.w3.org/TR/webauthn-2/#base64url-encoding
    STANDARD_ENCODING = :base64url

    class << self
      def lookup(encoding)
        case encoding
        when :base64
          Base64Encoder
        when :base64url
          Base64UrlEncoder
        when nil, false
          NullEncoder
        else
          raise "Unsupported or unknown encoding: #{encoding}"
        end
      end
    end

    class Base64Encoder
      def self.encode(data)
        [data].pack("m0") # Base64.strict_encode64(data)
      end

      def self.decode(data)
        data.unpack1("m0") # Base64.strict_decode64(data)
      end
    end

    class Base64UrlEncoder
      def self.encode(data)
        data = [data].pack("m0") # Base64.urlsafe_encode64(data, padding: false)
        data.chomp!("==") or data.chomp!("=")
        data.tr!("+/", "-_")
        data
      end

      def self.decode(data)
        if !data.end_with?("=") && data.length % 4 != 0 #  Base64.urlsafe_decode64(data)
          data = data.ljust((data.length + 3) & ~3, "=")
        end

        data = data.tr("-_", "+/")
        data.unpack1("m0")
      end
    end

    class NullEncoder
      def self.encode(data)
        data
      end

      def self.decode(data)
        data
      end
    end
  end
end
