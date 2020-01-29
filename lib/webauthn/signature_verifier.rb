# frozen_string_literal: true

require "cose"
require "cose/rsapkcs1_algorithm"
require "openssl"
require "webauthn/error"

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

    # This logic is a candidate to be moved to cose gem domain
    def cose_key_type
      case cose_algorithm
      when COSE::Algorithm::ECDSA
        COSE::Key::EC2::KTY_EC2
      when COSE::Algorithm::RSAPSS, RSAPKCS1Algorithm
        COSE::Key::RSA::KTY_RSA
      else
        raise UnsupportedAlgorithm, "Unsupported algorithm #{algorithm}"
      end
    end

    def validate
      if !cose_algorithm
        raise UnsupportedAlgorithm, "Unsupported algorithm #{algorithm}"
      elsif !supported_algorithms.include?(cose_algorithm.name)
        raise UnsupportedAlgorithm, "Unsupported algorithm #{algorithm}"
      elsif !KTY_MAP[cose_key_type].include?(public_key.class)
        raise("Incompatible algorithm and key")
      end
    end

    def supported_algorithms
      WebAuthn.configuration.algorithms
    end
  end
end
