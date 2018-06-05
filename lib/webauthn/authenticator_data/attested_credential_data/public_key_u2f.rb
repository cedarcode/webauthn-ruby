# frozen_string_literal: true

module WebAuthn
  class AuthenticatorData
    class AttestedCredentialData
      class PublicKeyU2f
        ALGORITHM_KEY = 3
        COORDINATE_LENGTH = 32
        X_COORDINATE_KEY = -2
        Y_COORDINATE_KEY = -3

        def initialize(data)
          @data = data
        end

        def valid?
          data.size >= COORDINATE_LENGTH * 2 &&
            x_coordinate.length == COORDINATE_LENGTH &&
            y_coordinate.length == COORDINATE_LENGTH &&
            algorithm == WebAuthn::COSE::ECDSA::ALG_ES256
        end

        def to_str
          "\x04" + x_coordinate + y_coordinate
        end

        private

        attr_reader :data

        def x_coordinate
          decoded_data[X_COORDINATE_KEY]
        end

        def y_coordinate
          decoded_data[Y_COORDINATE_KEY]
        end

        def algorithm
          decoded_data[ALGORITHM_KEY]
        end

        def decoded_data
          @decoded_data ||= CBOR.decode(data)
        end
      end
    end
  end
end
