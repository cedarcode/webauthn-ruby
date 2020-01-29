# frozen_string_literal: true

require "cose"
require "cose/rsapkcs1_algorithm"
require "openssl"
require "webauthn/error"

module WebAuthn
  class SignatureVerifier
    class UnsupportedAlgorithm < Error; end

    def initialize(algorithm, public_key)
      @algorithm = algorithm
      @public_key = public_key

      validate
    end

    def verify(signature, verification_data)
      cose_algorithm.verify(public_key, signature, verification_data)
    rescue COSE::Error
      false
    end

    private

    attr_reader :algorithm, :public_key

    def cose_algorithm
      case algorithm
      when COSE::Algorithm::Base
        algorithm
      else
        COSE::Algorithm.find(algorithm)
      end
    end

    def validate
      if !cose_algorithm
        raise UnsupportedAlgorithm, "Unsupported algorithm #{algorithm}"
      elsif !supported_algorithms.include?(cose_algorithm.name)
        raise UnsupportedAlgorithm, "Unsupported algorithm #{algorithm}"
      elsif !cose_algorithm.compatible_key?(public_key)
        raise("Incompatible algorithm and key")
      end
    end

    def supported_algorithms
      WebAuthn.configuration.algorithms
    end
  end
end
