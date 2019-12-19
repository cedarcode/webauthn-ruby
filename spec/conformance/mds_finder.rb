# frozen_string_literal: true

require 'fido_metadata'

class MDSFinder
  extend Forwardable

  def_delegator :fido_metadata_configuration, :cache_backend, :cache_backend
  def_delegator :fido_metadata_configuration, :cache_backend=, :cache_backend=
  def_delegator :fido_metadata_configuration, :metadata_token, :token
  def_delegator :fido_metadata_configuration, :metadata_token=, :token=

  def find(_format, aaguid: nil, attestation_certificate_key_id: nil)
    metadata_statement =
      if aaguid
        fido_metadata_store.fetch_statement(aaguid: aaguid)
      else
        fido_metadata_store.fetch_statement(attestation_certificate_key_id: attestation_certificate_key_id)
      end

    metadata_statement&.attestation_root_certificates || []
  end

  private

  def fido_metadata_store
    @fido_metadata_store ||= FidoMetadata::Store.new
  end

  def fido_metadata_configuration
    FidoMetadata.configuration
  end
end
