require "openssl"

module WebAuthn
  class StatementValidator
    VALID_ATTESTATION_CERTIFICATE_COUNT = 1

    def initialize(statement)
      @statement = statement
    end

    def valid?
      valid_format? && valid_attestation_public_key? && valid_signature?
    end

    private

    attr_reader :statement

    def valid_format?
      !!(raw_attestation_certificates && signature) && valid_attestation_certificate_count?
    end

    def valid_attestation_public_key?
      attestation_public_key.is_a?(OpenSSL::PKey::EC) && attestation_public_key.check_key
    end

    def valid_signature?
      raise NotImplementedError
    end

    def valid_attestation_certificate_count?
      raw_attestation_certificates.length == VALID_ATTESTATION_CERTIFICATE_COUNT
    end

    def attestation_certificate
      @attestation_certificate ||= OpenSSL::X509::Certificate.new(raw_attestation_certificates[0])
    end

    def attestation_public_key
      attestation_certificate.public_key
    end

    def raw_attestation_certificates
      statement["x5c"]
    end

    def signature
      statement["sig"]
    end
  end
end
