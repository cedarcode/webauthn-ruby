# frozen_string_literal: true

require "bindata"

module TPM
  # Section 10.4 in https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
  class SizedBuffer < BinData::Record
    endian :big

    uint16 :buffer_size, value: lambda { buffer.size }
    string :buffer, read_length: :buffer_size
  end
end
