# frozen_string_literal: true

require "cose/ecdsa"
require "cose/key"

module WebAuthn
  class AuthenticatorData
    class AttestedCredentialData
      class PublicKey
        COORDINATE_LENGTH = 32

        def initialize(data)
          @data = data
        end

        def valid?
          cose_key.is_a?(COSE::Key::EC2) &&
            data.size >= COORDINATE_LENGTH * 2 &&
            cose_key.x_coordinate.length == COORDINATE_LENGTH &&
            cose_key.y_coordinate.length == COORDINATE_LENGTH &&
            cose_key.algorithm == COSE::ECDSA::ALG_ES256
        rescue COSE::UnknownKeyType
          false
        end

        def to_str
          "\x04" + cose_key.x_coordinate + cose_key.y_coordinate
        end

        private

        attr_reader :data

        def cose_key
          @cose_key ||= COSE::Key.deserialize(data)
        end
      end
    end
  end
end
