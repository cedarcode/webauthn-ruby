# frozen_string_literal: true

require "openssl"

module WebAuthn
  class FidoU2fAttestationStatement
    VALID_ATTESTATION_CERTIFICATE_COUNT = 1

    def initialize(statement)
      @statement = statement
    end

    def valid?
      valid_format? && valid_certificate_public_key?
    end

    def certificate_public_key
      attestation_certificate.public_key
    end

    def signature
      statement["sig"]
    end

    private

    attr_reader :statement

    def valid_format?
      !!(raw_attestation_certificates && signature) &&
        raw_attestation_certificates.length == VALID_ATTESTATION_CERTIFICATE_COUNT
    end

    def valid_certificate_public_key?
      certificate_public_key.is_a?(OpenSSL::PKey::EC) && certificate_public_key.check_key
    end

    def attestation_certificate
      @attestation_certificate ||= OpenSSL::X509::Certificate.new(raw_attestation_certificates[0])
    end

    def raw_attestation_certificates
      statement["x5c"]
    end
  end
end
