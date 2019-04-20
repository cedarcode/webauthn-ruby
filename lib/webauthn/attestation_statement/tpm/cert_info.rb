# frozen_string_literal: true

require "tpm/constants"
require "tpm/s_attest"

module WebAuthn
  module AttestationStatement
    class TPM < Base
      class CertInfo
        def initialize(data)
          @data = data
        end

        def valid?(attested_name, extra_data)
          s_attest.magic == ::TPM::GENERATED_VALUE &&
            s_attest.attested.name.buffer == attested_name &&
            s_attest.extra_data.buffer == extra_data
        end

        private

        attr_reader :data

        def s_attest
          @s_attest ||= ::TPM::SAttest.read(data)
        end
      end
    end
  end
end
