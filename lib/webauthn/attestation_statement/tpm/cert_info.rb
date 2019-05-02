# frozen_string_literal: true

require "openssl"
require "tpm/constants"
require "tpm/s_attest"
require "webauthn/attestation_statement/base"

module WebAuthn
  module AttestationStatement
    class TPM < Base
      class CertInfo
        TPM_TO_OPENSSL_HASH_ALG = {
          ::TPM::ALG_SHA1 => "SHA1",
          ::TPM::ALG_SHA256 => "SHA256"
        }.freeze

        def initialize(data)
          @data = data
        end

        def valid?(attested_data, extra_data)
          s_attest.magic == ::TPM::GENERATED_VALUE &&
            valid_name?(attested_data) &&
            s_attest.extra_data.buffer == extra_data
        end

        private

        attr_reader :data

        def valid_name?(attested_data)
          name_hash_alg = s_attest.attested.name.buffer[0..1].unpack("n")[0]
          name = s_attest.attested.name.buffer[2..-1]

          name == OpenSSL::Digest.digest(TPM_TO_OPENSSL_HASH_ALG[name_hash_alg], attested_data)
        end

        def s_attest
          @s_attest ||= ::TPM::SAttest.read(data)
        end
      end
    end
  end
end
