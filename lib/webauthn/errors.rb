# frozen_string_literal: true

module WebAuthn

  # Generic WebAuthn exception class
  class WebAuthnError < StandardError; end

  class AttestationFormatNotSupported < WebAuthnError
    def initialize(attestation_format)
      super("Unsupported attestation format '#{attestation_format}'")
    end
  end

  class ClientDataMissing < WebAuthnError
    def initialize
      super("Client Data JSON is missing")
    end
  end
end
