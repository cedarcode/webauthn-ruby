# frozen_string_literal: true

# TODO: Move this to cose gem
module COSE
  module Algorithm
    # https://tools.ietf.org/html/rfc8152#section-8.1
    ECDSA = Struct.new(:id, :name, :hash, :key_curve) do
      @registered = {}

      def self.register(id, name, hash, key_curve)
        @registered[id] = COSE::Algorithm::ECDSA.new(id, name, hash, key_curve)
      end

      def self.find(id)
        @registered[id]
      end

      def self.by_name(name)
        @registered.values.detect { |algorithm| algorithm.name == name }
      end

      def value
        id
      end
    end
  end
end

COSE::Algorithm::ECDSA.register(-7, "ES256", "SHA256", "prime256v1")
