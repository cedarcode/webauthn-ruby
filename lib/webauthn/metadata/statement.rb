# frozen_string_literal: true

require "webauthn/metadata/attributes"
require "webauthn/metadata/constants"
require "webauthn/metadata/verification_method_descriptor"
require "webauthn/metadata/coercer/assumed_value"
require "webauthn/metadata/coercer/bit_field"
require "webauthn/metadata/coercer/certificates"
require "webauthn/metadata/coercer/magic_number"
require "webauthn/metadata/coercer/user_verification_details"

module WebAuthn
  module Metadata
    class Statement
      extend Attributes

      json_accessor("legalHeader")
      json_accessor("aaid")
      json_accessor("aaguid")
      json_accessor("attestationCertificateKeyIdentifiers")
      json_accessor("description")
      json_accessor("alternativeDescriptions")
      json_accessor("authenticatorVersion")
      json_accessor("protocolFamily", Coercer::AssumedValue.new("uaf"))
      json_accessor("upv")
      json_accessor("assertionScheme")
      json_accessor("authenticationAlgorithm", Coercer::MagicNumber.new(Constants::AUTHENTICATION_ALGORITHMS))
      json_accessor("authenticationAlgorithms",
                    Coercer::MagicNumber.new(Constants::AUTHENTICATION_ALGORITHMS, array: true))
      json_accessor("publicKeyAlgAndEncoding", Coercer::MagicNumber.new(Constants::PUBLIC_KEY_FORMATS))
      json_accessor("publicKeyAlgAndEncodings",
                    Coercer::MagicNumber.new(Constants::PUBLIC_KEY_FORMATS, array: true))
      json_accessor("attestationTypes", Coercer::MagicNumber.new(Constants::ATTESTATION_TYPES, array: true))
      json_accessor("userVerificationDetails", Coercer::UserVerificationDetails)
      json_accessor("keyProtection", Coercer::BitField.new(Constants::KEY_PROTECTION_TYPES))
      json_accessor("isKeyRestricted", Coercer::AssumedValue.new(true))
      json_accessor("isFreshUserVerificationRequired", Coercer::AssumedValue.new(true))
      json_accessor("matcherProtection",
                    Coercer::BitField.new(Constants::MATCHER_PROTECTION_TYPES, single_value: true))
      json_accessor("cryptoStrength")
      json_accessor("operatingEnv")
      json_accessor("attachmentHint", Coercer::BitField.new(Constants::ATTACHMENT_HINTS))
      json_accessor("isSecondFactorOnly")
      json_accessor("tcDisplay", Coercer::BitField.new(Constants::TRANSACTION_CONFIRMATION_DISPLAY_TYPES))
      json_accessor("tcDisplayContentType")
      json_accessor("tcDisplayPNGCharacteristics")
      json_accessor("attestationRootCertificates", Coercer::Certificates)
      json_accessor("ecdaaTrustAnchors")
      json_accessor("icon")
      json_accessor("supportedExtensions")
    end
  end
end
