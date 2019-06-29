# frozen_string_literal: true

require "webauthn/metadata/attributes"

module WebAuthn
  module Metadata
    class PatternAccuracyDescriptor
      extend Attributes

      json_accessor("minComplexity")
      json_accessor("maxRetries")
      json_accessor("blockSlowdown")
    end
  end
end
