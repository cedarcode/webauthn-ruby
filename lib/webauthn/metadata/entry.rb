# frozen_string_literal: true

require "webauthn/metadata/attributes"
require "webauthn/metadata/biometric_status_report"
require "webauthn/metadata/status_report"
require "webauthn/metadata/coercer/date"
require "webauthn/metadata/coercer/escaped_uri"
require "webauthn/metadata/coercer/objects"

module WebAuthn
  module Metadata
    class Entry
      extend Attributes

      json_accessor("aaid")
      json_accessor("aaguid")
      json_accessor("attestationCertificateKeyIdentifiers")
      json_accessor("hash")
      json_accessor("url", Coercer::EscapedURI)
      json_accessor("biometricStatusReports", Coercer::Objects.new(BiometricStatusReport))
      json_accessor("statusReports", Coercer::Objects.new(StatusReport))
      json_accessor("timeOfLastStatusChange", Coercer::Date)
      json_accessor("rogueListURL", Coercer::EscapedURI)
      json_accessor("rogueListHash")
    end
  end
end
