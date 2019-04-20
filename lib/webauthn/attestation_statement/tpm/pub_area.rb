# frozen_string_literal: true

require "cose/key"
require "tpm/constants"
require "tpm/t_public"

module WebAuthn
  module AttestationStatement
    class TPM < Base
      class PubArea
        BYTE_LENGTH = 8

        COSE_TO_TPM_ALG = {
          COSE::Algorithm.by_name("ES256").id => ::TPM::ALG_ECDSA,
          COSE::Algorithm.by_name("RS256").id => ::TPM::ALG_RSASSA
        }.freeze

        COSE_TO_TPM_CURVE = {
          COSE::Key::EC2::CRV_P256 => ::TPM::ECC_NIST_P256
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
          t_public.parameters.symmetric == ::TPM::ALG_NULL &&
            (
              t_public.parameters.scheme == ::TPM::ALG_NULL ||
              t_public.parameters.scheme == COSE_TO_TPM_ALG[cose_key.alg]
            ) &&
            t_public.parameters.curve_id == COSE_TO_TPM_CURVE[cose_key.crv] &&
            t_public.unique.buffer == cose_key.x + cose_key.y
        end

        def valid_rsa_key?(cose_key)
          t_public.parameters.symmetric == ::TPM::ALG_NULL &&
            (
              t_public.parameters.scheme == ::TPM::ALG_NULL ||
              t_public.parameters.scheme == COSE_TO_TPM_ALG[cose_key.alg]
            ) &&
            t_public.parameters.key_bits == cose_key.n.size * BYTE_LENGTH &&
            t_public.unique.buffer == cose_key.n
        end

        def t_public
          @t_public = ::TPM::TPublic.read(data)
        end
      end
    end
  end
end
