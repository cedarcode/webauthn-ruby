# frozen_string_literal: true

require "cose"
require "cose/not_implemented_algorithm"
require "tpm/constants"
require "tpm/t_public"
require "webauthn/attestation_statement/base"

module WebAuthn
  module AttestationStatement
    class TPM < Base
      class PubArea
        BYTE_LENGTH = 8

        COSE_ECC_TO_TPM_ALG = {
          COSE::Algorithm.by_name("ES256").id => ::TPM::ALG_ECDSA,
        }.freeze

        COSE_RSA_TO_TPM_ALG = {
          COSE::Algorithm.by_name("RS256").id => ::TPM::ALG_RSASSA,
          COSE::Algorithm.by_name("PS256").id => ::TPM::ALG_RSAPSS,
        }.freeze

        COSE_TO_TPM_CURVE = {
          COSE::Key::Curve.by_name("P-256").id => ::TPM::ECC_NIST_P256
        }.freeze

        def initialize(data)
          @data = data
        end

        def valid?(public_key)
          cose_key = COSE::Key.deserialize(public_key)

          case cose_key
          when COSE::Key::EC2
            valid_ecc_key?(cose_key)
          when COSE::Key::RSA
            valid_rsa_key?(cose_key)
          else
            raise "Unsupported or unknown TPM key type"
          end
        end

        private

        attr_reader :data

        def valid_ecc_key?(cose_key)
          valid_symmetric? &&
            valid_scheme?(COSE_ECC_TO_TPM_ALG[cose_key.alg]) &&
            parameters.curve_id == COSE_TO_TPM_CURVE[cose_key.crv] &&
            unique == cose_key.x + cose_key.y
        end

        def valid_rsa_key?(cose_key)
          valid_symmetric? &&
            valid_scheme?(COSE_RSA_TO_TPM_ALG[cose_key.alg]) &&
            parameters.key_bits == cose_key.n.size * BYTE_LENGTH &&
            unique == cose_key.n
        end

        def valid_symmetric?
          parameters.symmetric == ::TPM::ALG_NULL
        end

        def valid_scheme?(scheme)
          parameters.scheme == ::TPM::ALG_NULL || parameters.scheme == scheme
        end

        def unique
          t_public.unique.buffer
        end

        def parameters
          t_public.parameters
        end

        def t_public
          @t_public = ::TPM::TPublic.read(data)
        end
      end
    end
  end
end
