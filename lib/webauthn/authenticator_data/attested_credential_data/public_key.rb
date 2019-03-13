# frozen_string_literal: true

require "cose/ecdsa"
require "cose/key/ec2"

module WebAuthn
  class AuthenticatorData
    class AttestedCredentialData
      class PublicKey
        COORDINATE_LENGTH = 32

        def initialize(data)
          @data = data
        end

        def valid?
          data.size >= COORDINATE_LENGTH * 2 &&
            cose_key.x_coordinate.length == COORDINATE_LENGTH &&
            cose_key.y_coordinate.length == COORDINATE_LENGTH &&
            cose_key.algorithm == COSE::ECDSA::ALG_ES256
        end

        def to_str
          "\x04" + cose_key.x_coordinate + cose_key.y_coordinate
        end

        private

        attr_reader :data

        def cose_key
          @cose_key ||= COSE::Key::EC2.deserialize(data)
        end
      end
    end
  end
end
