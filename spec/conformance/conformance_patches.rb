# frozen_string_literal: true

require "tpm/key_attestation"

::TPM.send(:remove_const, "VENDOR_IDS")
::TPM::VENDOR_IDS = { "id:FFFFF1D0" => "FIDO Alliance" }.freeze

module TPM
  class Tpm2bName < BinData::Record
    # Needed to workaround https://github.com/fido-alliance/conformance-tools-issues/issues/396
    def valid_for?(object)
      name.digest == OpenSSL::Digest.digest(TPM::TPM_TO_OPENSSL_HASH_ALG[name.hash_alg], object)
    end
  end
end
