# frozen_string_literal: true

require "webauthn/metadata/attributes"
require "webauthn/metadata/coercer/date"
require "webauthn/metadata/coercer/escaped_uri"

module WebAuthn
  module Metadata
    class StatusReport
      extend Attributes

      json_accessor("status")
      json_accessor("effectiveDate", Coercer::Date)
      json_accessor("certificate")
      json_accessor("url", Coercer::EscapedURI)
      json_accessor("certificationDescriptor")
      json_accessor("certificateNumber")
      json_accessor("certificationPolicyVersion")
      json_accessor("certificationRequirementsVersion")
    end
  end
end
