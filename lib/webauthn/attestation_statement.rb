# frozen_string_literal: true

module WebAuthn
  module AttestationStatement
    ATTESTATION_FORMAT_NONE = "none"
    ATTESTATION_FORMAT_FIDO_U2F = "fido-u2f"

    def self.from(format, statement)
      case format
      when ATTESTATION_FORMAT_NONE
        require "webauthn/attestation_statement/none"
        WebAuthn::AttestationStatement::None.new(statement)
      when ATTESTATION_FORMAT_FIDO_U2F
        require "webauthn/attestation_statement/fido_u2f"
        WebAuthn::AttestationStatement::FidoU2f.new(statement)
      else
        raise "Unsupported attestation format '#{attestation_format}'"
      end
    end
  end
end
