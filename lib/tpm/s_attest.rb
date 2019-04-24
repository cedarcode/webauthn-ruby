# frozen_string_literal: true

require "bindata"
require "tpm/constants"
require "tpm/sized_buffer"
require "tpm/s_attest/s_certify_info"

module TPM
  # Section 10.12.8 in https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
  class SAttest < BinData::Record
    endian :big

    uint32 :magic
    uint16 :attested_type
    sized_buffer :qualified_signer
    sized_buffer :extra_data

    # s_clock_info :clock_info
    # uint64 :firmware_version
    skip length: 25

    choice :attested, selection: :attested_type do
      s_certify_info TPM::ST_ATTEST_CERTIFY
    end
  end
end
