# frozen_string_literal: true

require "webauthn/metadata/attributes"

module WebAuthn
  module Metadata
    class BiometricAccuracyDescriptor
      extend Attributes

      json_accessor("selfAttestedFRR")
      json_accessor("selfAttestedFAR")
      json_accessor("maxTemplates")
      json_accessor("maxRetries")
      json_accessor("blockSlowdown")
    end
  end
end
