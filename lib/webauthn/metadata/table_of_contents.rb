# frozen_string_literal: true

require "webauthn/metadata/attributes"
require "webauthn/metadata/entry"
require "webauthn/metadata/coercer/date"
require "webauthn/metadata/coercer/objects"

module WebAuthn
  module Metadata
    class TableOfContents
      extend Attributes

      json_accessor("legalHeader")
      json_accessor("nextUpdate", Coercer::Date)
      json_accessor("entries", Coercer::Objects.new(Entry))
      json_accessor("no")
    end
  end
end
