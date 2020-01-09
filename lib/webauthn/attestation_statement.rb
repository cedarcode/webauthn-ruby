# frozen_string_literal: true

require "webauthn/attestation_statement/android_key"
require "webauthn/attestation_statement/android_safetynet"
require "webauthn/attestation_statement/fido_u2f"
require "webauthn/attestation_statement/none"
require "webauthn/attestation_statement/packed"
require "webauthn/attestation_statement/tpm"
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

    def self.from(format, statement)
      case format
      when ATTESTATION_FORMAT_NONE
        WebAuthn::AttestationStatement::None.new(statement)
      when ATTESTATION_FORMAT_FIDO_U2F
        WebAuthn::AttestationStatement::FidoU2f.new(statement)
      when ATTESTATION_FORMAT_PACKED
        WebAuthn::AttestationStatement::Packed.new(statement)
      when ATTESTATION_FORMAT_ANDROID_SAFETYNET
        WebAuthn::AttestationStatement::AndroidSafetynet.new(statement)
      when ATTESTATION_FORMAT_ANDROID_KEY
        WebAuthn::AttestationStatement::AndroidKey.new(statement)
      when ATTESTATION_FORMAT_TPM
        WebAuthn::AttestationStatement::TPM.new(statement)
      else
        raise FormatNotSupportedError, "Unsupported attestation format '#{format}'"
      end
    end
  end
end
