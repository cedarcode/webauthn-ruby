# frozen_string_literal: true

require "tpm/constants"

::TPM.send(:remove_const, "VENDOR_IDS")
::TPM::VENDOR_IDS = { "id:FFFFF1D0" => "FIDO Alliance" }.freeze
