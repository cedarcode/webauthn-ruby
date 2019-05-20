# frozen_string_literal: true

require "uri"

module WebAuthn
  module Metadata
    module Coercer
      module EscapedURI
        # The character # is a reserved character and not allowed in URLs, it is replaced by its hex value %x23.
        # https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-service-v2.0-rd-20180702.html#idl-def-MetadataTOCPayloadEntry
        def self.coerce(value)
          return value if value.is_a?(URI)

          URI(value.gsub(/%x23/, '#')) if value
        end
      end
    end
  end
end
