# frozen_string_literal: true

require 'webauthn/attestation_statement/base'

module WebAuthn
  module AttestationStatement
    ATTESTATION_FORMAT_NONE = "none"
    ATTESTATION_FORMAT_FIDO_U2F = "fido-u2f"
    ATTESTATION_FORMAT_PACKED = 'packed'

    def self.from(format, statement)
      case format
      when ATTESTATION_FORMAT_NONE
        require "webauthn/attestation_statement/none"
        WebAuthn::AttestationStatement::None.new(statement)
      when ATTESTATION_FORMAT_FIDO_U2F
        require "webauthn/attestation_statement/fido_u2f"
        WebAuthn::AttestationStatement::FidoU2f.new(statement)
      when ATTESTATION_FORMAT_PACKED
        require "webauthn/attestation_statement/packed"
        WebAuthn::AttestationStatement::Packed.new(statement)
      else
        raise WebAuthn::AttestationStatement::Base::NotSupportedError, "Unsupported attestation format '#{format}'"
      end
    end
  end
end
