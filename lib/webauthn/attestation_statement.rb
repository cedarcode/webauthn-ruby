# frozen_string_literal: true

require "webauthn/error"

module WebAuthn
  module AttestationStatement
    class FormatNotSupportedError < Error; end

    ATTESTATION_FORMAT_NONE = "none"
    ATTESTATION_FORMAT_FIDO_U2F = "fido-u2f"
    ATTESTATION_FORMAT_PACKED = 'packed'
    ATTESTATION_FORMAT_ANDROID_SAFETYNET = "android-safetynet"
    ATTESTATION_FORMAT_ANDROID_KEY = "android-key"
    ATTESTATION_FORMAT_TPM = "tpm"

    ATTESTATION_TYPE_NONE = "None"
    ATTESTATION_TYPE_BASIC = "Basic"
    ATTESTATION_TYPE_SELF = "Self"
    ATTESTATION_TYPE_ATTCA = "AttCA"
    ATTESTATION_TYPE_ECDAA = "ECDAA"
    ATTESTATION_TYPE_BASIC_OR_ATTCA = "Basic_or_AttCA"

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
      when ATTESTATION_FORMAT_ANDROID_KEY
        require "webauthn/attestation_statement/android_key"
        WebAuthn::AttestationStatement::AndroidKey.new(statement)
      when ATTESTATION_FORMAT_TPM
        require "webauthn/attestation_statement/tpm"
        WebAuthn::AttestationStatement::TPM.new(statement)
      else
        raise FormatNotSupportedError, "Unsupported attestation format '#{format}'"
      end
    end
  end
end
