# frozen_string_literal: true

require "webauthn/attestation_statement/base"

module WebAuthn
  module Metadata
    module Constants
      # https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html

      ATTACHMENT_HINTS = {
        0x0001 => "INTERNAL",
        0x0002 => "EXTERNAL",
        0x0004 => "WIRED",
        0x0008 => "WIRELESS",
        0x0010 => "NFC",
        0x0020 => "BLUETOOTH",
        0x0040 => "NETWORK",
        0x0080 => "READY",
        0x0100 => "WIFI_DIRECT",
      }.freeze

      ATTESTATION_TYPES = {
        0x3E07 => WebAuthn::AttestationStatement::ATTESTATION_TYPE_BASIC, # BASIC_FULL in FIDO registry
        0x3E08 => WebAuthn::AttestationStatement::ATTESTATION_TYPE_SELF, # BASIC_SURROGATE in FIDO registry
        0x3E09 => WebAuthn::AttestationStatement::ATTESTATION_TYPE_ECDAA,
        0x3E0A => WebAuthn::AttestationStatement::ATTESTATION_TYPE_ATTCA,
      }.freeze

      AUTHENTICATION_ALGORITHMS = {
        0x0001 => "SECP256R1_ECDSA_SHA256_RAW",
        0x0002 => "SECP256R1_ECDSA_SHA256_DER",
        0x0003 => "RSASSA_PSS_SHA256_RAW",
        0x0004 => "RSASSA_PSS_SHA256_DER",
        0x0005 => "SECP256K1_ECDSA_SHA256_RAW",
        0x0006 => "SECP256K1_ECDSA_SHA256_DER",
        0x0007 => "SM2_SM3_RAW",
        0x0008 => "RSA_EMSA_PKCS1_SHA256_RAW",
        0x0009 => "RSA_EMSA_PKCS1_SHA256_DER",
        0x000A => "RSASSA_PSS_SHA384_RAW",
        0x000B => "RSASSA_PSS_SHA512_RAW",
        0x000C => "RSASSA_PKCSV15_SHA256_RAW",
        0x000D => "RSASSA_PKCSV15_SHA384_RAW",
        0x000E => "RSASSA_PKCSV15_SHA512_RAW",
        0x000F => "RSASSA_PKCSV15_SHA1_RAW",
        0x0010 => "SECP384R1_ECDSA_SHA384_RAW",
        0x0011 => "SECP521R1_ECDSA_SHA512_RAW",
        0x0012 => "ED25519_EDDSA_SHA256_RAW",
      }.freeze

      KEY_PROTECTION_TYPES = {
        0x0001 => "SOFTWARE",
        0x0002 => "HARDWARE",
        0x0004 => "TEE",
        0x0008 => "SECURE_ELEMENT",
        0x0010 => "REMOTE_HANDLE",
      }.freeze

      MATCHER_PROTECTION_TYPES = {
        0x0001 => "SOFTWARE",
        0x0002 => "TEE",
        0x0004 => "ON_CHIP",
      }.freeze

      PUBLIC_KEY_FORMATS = {
        0x0100 => "ECC_X962_RAW",
        0x0101 => "ECC_X962_DER",
        0x0102 => "RSA_2048_RAW",
        0x0103 => "RSA_2048_DER",
        0x0104 => "COSE",
      }.freeze

      TRANSACTION_CONFIRMATION_DISPLAY_TYPES = {
        0x0001 => "ANY",
        0x0002 => "PRIVILEGED_SOFTWARE",
        0x0004 => "TEE",
        0x0008 => "HARDWARE",
        0x0010 => "REMOTE",
      }.freeze

      USER_VERIFICATION_METHODS = {
        0x00000001 => "PRESENCE",
        0x00000002 => "FINGERPRINT",
        0x00000004 => "PASSCODE",
        0x00000008 => "VOICEPRINT",
        0x00000010 => "FACEPRINT",
        0x00000020 => "LOCATION",
        0x00000040 => "EYEPRINT",
        0x00000080 => "PATTERN",
        0x00000100 => "HANDPRINT",
        0x00000200 => "NONE",
        0x00000400 => "ALL",
      }.freeze
    end
  end
end
