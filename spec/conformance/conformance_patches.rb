# frozen_string_literal: true

require "webauthn/attestation_statement/tpm"

::TPM.send(:remove_const, "VENDOR_IDS")
::TPM::VENDOR_IDS = { "id:FFFFF1D0" => "FIDO Alliance" }.freeze

module FidoTrustStore
  def certificate_chain_trusted?(_trust_store, aaguid)
    find_metadata(aaguid)

    super(fido_metadata_statement.trust_store, aaguid)
  end
end
WebAuthn::AttestationStatement::TPM.prepend(FidoTrustStore)
