# frozen_string_literal: true

module WebAuthn
  # COSE module has the potential to being extracted out of WebAuthn
  module COSE
    module Key
      class EC2
        KTY_LABEL = 1
        ALG_LABEL = 3

        CRV_LABEL = -1
        X_LABEL = -2
        Y_LABEL = -3

        KTY_EC2 = 2

        attr_reader :algorithm, :curve, :x_coordinate, :y_coordinate

        def initialize(algorithm: nil, curve:, x_coordinate:, y_coordinate:)
          if !curve
            raise ArgumentError, "Required curve is missing"
          elsif !x_coordinate
            raise ArgumentError, "Required x-coordinate is missing"
          elsif !y_coordinate
            raise ArgumentError, "Required y-coordinate is missing"
          else
            @algorithm = algorithm
            @curve = curve
            @x_coordinate = x_coordinate
            @y_coordinate = y_coordinate
          end
        end

        def self.from_map(map)
          if map[KTY_LABEL] == KTY_EC2
            new(
              algorithm: map[ALG_LABEL],
              curve: map[CRV_LABEL],
              x_coordinate: map[X_LABEL],
              y_coordinate: map[Y_LABEL]
            )
          else
            raise "Not an EC2 key"
          end
        end

        def self.from_cbor(cbor)
          from_map(CBOR.decode(cbor))
        end
      end
    end
  end
end
