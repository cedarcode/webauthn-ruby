# frozen_string_literal: true

require "base64"
require "webauthn/encoders"

module WebAuthn
  def self.standard_encoder
    @standard_encoder ||= Encoder.new
  end

  class Encoder
    extend Forwardable

    # https://www.w3.org/TR/webauthn-2/#base64url-encoding
    STANDARD_ENCODING = :base64url

    def_delegators :@encoder_klass, :encode, :decode

    def initialize(encoding = STANDARD_ENCODING)
      @encoder_klass =
        case encoding
        when :base64
          Encoders::Base64Encoder
        when :base64url
          Encoders::Base64URLEncoder
        when nil, false
          Encoders::NullEncoder
        else
          raise "Unsupported or unknown encoding: #{encoding}"
        end
    end
  end
end
