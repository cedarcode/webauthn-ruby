# frozen_string_literal: true

require "webauthn/metadata/attributes"

module WebAuthn
  module Metadata
    class CodeAccuracyDescriptor
      extend Attributes

      json_accessor("base")
      json_accessor("minLength")
      json_accessor("maxRetries")
      json_accessor("blockSlowdown")
    end
  end
end
