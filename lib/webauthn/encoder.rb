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

    def initialize(*args)
      @encoder_klass = Encoders.lookup(*args)
    end
  end
end
