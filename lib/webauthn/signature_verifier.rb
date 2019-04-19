# frozen_string_literal: true

require "cose/algorithm"

module WebAuthn
  class SignatureVerifier
    class UnsupportedAlgorithm < Error; end

    def initialize(algorithm, public_key)
      @algorithm = algorithm
      @public_key = public_key
    end

    def verify(signature, verification_data)
      if cose_algorithm
        public_key.verify(cose_algorithm.hash, signature, verification_data)
      else
        raise UnsupportedAlgorithm, "Unsupported algorithm #{algorithm}"
      end
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
  end
end
