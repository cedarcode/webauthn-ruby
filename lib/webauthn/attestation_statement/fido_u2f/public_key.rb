# frozen_string_literal: true

require "cose/algorithm"
require "cose/key/ec2"
require "webauthn/attestation_statement/base"

module WebAuthn
  module AttestationStatement
    class FidoU2f < Base
      class PublicKey
        COORDINATE_LENGTH = 32
        UNCOMPRESSED_FORM_INDICATOR = "\x04"

        def self.uncompressed_point?(data)
          data.size &&
            data.length == UNCOMPRESSED_FORM_INDICATOR.length + COORDINATE_LENGTH * 2 &&
            data[0] == UNCOMPRESSED_FORM_INDICATOR
        end

        def initialize(data)
          @data = data
        end

        def valid?
          data.size >= COORDINATE_LENGTH * 2 &&
            cose_key.x.length == COORDINATE_LENGTH &&
            cose_key.y.length == COORDINATE_LENGTH &&
            cose_key.alg == COSE::Algorithm.by_name("ES256").id
        end

        def to_uncompressed_point
          UNCOMPRESSED_FORM_INDICATOR + cose_key.x + cose_key.y
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
