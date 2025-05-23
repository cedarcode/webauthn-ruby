# frozen_string_literal: true

require "webauthn/encoders"

module WebAuthn
  class Encoder
    extend Forwardable

    # https://www.w3.org/TR/webauthn-2/#base64url-encoding
    STANDARD_ENCODING = :base64url

    def_delegators :@encoder_klass, :encode, :decode

    def initialize(encoding = STANDARD_ENCODING)
      @encoder_klass = Encoders.lookup(encoding)
    end
  end
end
