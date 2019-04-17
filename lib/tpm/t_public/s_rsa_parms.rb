# frozen_string_literal: true

require "bindata"

module TPM
  class TPublic < BinData::Record
    # Section 12.2.3.5 in https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
    class SRsaParms < BinData::Record
      endian :big

      uint16 :symmetric
      uint16 :scheme
      uint16 :key_bits
      uint32 :exponent
    end
  end
end
