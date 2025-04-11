# frozen_string_literal: true

require "base64"
require "webauthn/encoders"

module WebAuthn
  class Encoder
    extend Forwardable

    def_delegators :@encoder_klass, :encode, :decode

    def initialize(encoding = Encoders::STANDARD_ENCODING)
      @encoder_klass = Encoders.lookup(encoding)
    end
  end
end
