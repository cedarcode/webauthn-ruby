# frozen_string_literal: true

require "openssl"
require "webauthn/attestation_statement/base"

module WebAuthn
  module AttestationStatement
    class FidoU2f < Base
      VALID_ATTESTATION_CERTIFICATE_COUNT = 1

      def valid?(authenticator_data, client_data_hash)
        valid_format? &&
          valid_certificate_public_key? &&
          valid_signature?(authenticator_data, client_data_hash)
      end

      private

      def signature
        statement["sig"]
      end

      def valid_format?
        !!(raw_attestation_certificates && signature) &&
          raw_attestation_certificates.length == VALID_ATTESTATION_CERTIFICATE_COUNT
      end

      def valid_certificate_public_key?
        certificate_public_key.is_a?(OpenSSL::PKey::EC) && certificate_public_key.check_key
      end

      def certificate_public_key
        attestation_certificate.public_key
      end

      def attestation_certificate
        @attestation_certificate ||= OpenSSL::X509::Certificate.new(raw_attestation_certificates[0])
      end

      def raw_attestation_certificates
        statement["x5c"]
      end

      def valid_signature?(authenticator_data, client_data_hash)
        certificate_public_key.verify(
          "SHA256",
          signature,
          verification_data(authenticator_data, client_data_hash)
        )
      end

      def verification_data(authenticator_data, client_data_hash)
        "\x00" +
          authenticator_data.rp_id_hash +
          client_data_hash +
          authenticator_data.credential.id +
          authenticator_data.credential.public_key
      end
    end
  end
end
