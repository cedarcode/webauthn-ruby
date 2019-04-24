# frozen_string_literal: true

require "bindata"
require "tpm/sized_buffer"

module TPM
  class SAttest < BinData::Record
    # Section 10.12.3 in https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
    class SCertifyInfo < BinData::Record
      sized_buffer :name
      sized_buffer :qualified_name
    end
  end
end
