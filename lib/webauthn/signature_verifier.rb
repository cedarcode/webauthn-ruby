# frozen_string_literal: true

require "cose"
require "cose/rsassa_algorithm"
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

    def verify(signature, verification_data, rsa_pss_salt_length: :digest)
      if rsa_pss?
        public_key.verify_pss(cose_algorithm.hash_function, signature, verification_data,
                              salt_length: rsa_pss_salt_length, mgf1_hash: cose_algorithm.hash_function)
      else
        public_key.verify(cose_algorithm.hash_function, signature, verification_data)
      end
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
      when COSE::Algorithm::RSAPSS, RSASSAAlgorithm
        COSE::Key::RSA::KTY_RSA
      else
        raise UnsupportedAlgorithm, "Unsupported algorithm #{algorithm}"
      end
    end

    def rsa_pss?
      cose_algorithm.name.start_with?("PS")
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
