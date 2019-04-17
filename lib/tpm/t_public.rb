# frozen_string_literal: true

require "bindata"
require "tpm/constants"
require "tpm/sized_buffer"
require "tpm/t_public/s_ecc_parms"
require "tpm/t_public/s_rsa_parms"

module TPM
  # Section 12.2.4 in https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
  class TPublic < BinData::Record
    endian :big

    uint16 :alg_type
    uint16 :name_alg

    # :object_attributes
    skip length: 4

    sized_buffer :auth_policy

    choice :parameters, selection: :alg_type do
      s_ecc_parms TPM::ALG_ECC
      s_rsa_parms TPM::ALG_RSA
    end

    choice :unique, selection: :alg_type do
      sized_buffer TPM::ALG_ECC
      sized_buffer TPM::ALG_RSA
    end
  end
end
