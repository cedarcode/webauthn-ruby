# frozen_string_literal: true

require "webauthn/metadata/attributes"
require "webauthn/metadata/biometric_accuracy_descriptor"
require "webauthn/metadata/constants"
require "webauthn/metadata/code_accuracy_descriptor"
require "webauthn/metadata/pattern_accuracy_descriptor"
require "webauthn/metadata/coercer/magic_number"
require "webauthn/metadata/coercer/objects"

module WebAuthn
  module Metadata
    class VerificationMethodDescriptor
      extend Attributes

      json_accessor("userVerification", Coercer::MagicNumber.new(Constants::USER_VERIFICATION_METHODS))
      json_accessor("caDesc")
      json_accessor("baDesc")
      json_accessor("paDesc")
    end
  end
end
