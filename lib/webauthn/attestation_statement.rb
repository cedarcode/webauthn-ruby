# frozen_string_literal: true

module WebAuthn
  module AttestationStatement
    class FormatNotSupportedError < StandardError; end

    ATTESTATION_FORMAT_NONE = "none"
    ATTESTATION_FORMAT_FIDO_U2F = "fido-u2f"
    ATTESTATION_FORMAT_PACKED = 'packed'
    ATTESTATION_FORMAT_ANDROID_SAFETYNET = "android-safetynet"

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
      when ATTESTATION_FORMAT_ANDROID_SAFETYNET
        require "webauthn/attestation_statement/android_safetynet"
        WebAuthn::AttestationStatement::AndroidSafetynet.new(statement)
      else
        raise FormatNotSupportedError, "Unsupported attestation format '#{format}'"
      end
    end
  end
end
