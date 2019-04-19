# frozen_string_literal: true

require "cose/algorithm"

module WebAuthn
  class SignatureVerifier
    class UnsupportedAlgorithm < Error; end

    # This logic contained in this map constant is a candidate to be moved to cose gem domain
    KTY_MAP = {
      COSE::Key::EC2::KTY_EC2 => [OpenSSL::PKey::EC, OpenSSL::PKey::EC::Point],
      COSE::Key::RSA::KTY_RSA => [OpenSSL::PKey::RSA]
    }.freeze

    def initialize(algorithm, public_key)
      @algorithm = algorithm
      @public_key = public_key

      validate
    end

    def verify(signature, verification_data)
      public_key.verify(cose_algorithm.hash, signature, verification_data)
    end

    private

    attr_reader :algorithm, :public_key

    def cose_algorithm
      case algorithm
      when COSE::Algorithm
        algorithm
      else
        COSE::Algorithm.find(algorithm)
      end
    end

    def validate
      if cose_algorithm
        if !KTY_MAP[cose_algorithm.kty].include?(public_key.class)
          raise("Incompatible algorithm and key")
        end
      else
        raise UnsupportedAlgorithm, "Unsupported algorithm #{algorithm}"
      end
    end
  end
end
