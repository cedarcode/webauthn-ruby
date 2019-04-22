# frozen_string_literal: true

require "openssl"
require "webauthn/attestation_statement/base"
require "webauthn/attestation_statement/fido_u2f/public_key"
require "webauthn/signature_verifier"

module WebAuthn
  module AttestationStatement
    class FidoU2f < Base
      VALID_ATTESTATION_CERTIFICATE_COUNT = 1
      VALID_ATTESTATION_CERTIFICATE_ALGORITHM = COSE::Algorithm.by_name("ES256")
      VALID_ATTESTED_AAGUID = 0.chr * WebAuthn::AuthenticatorData::AttestedCredentialData::AAGUID_LENGTH

      def valid?(authenticator_data, client_data_hash)
        valid_format? &&
          valid_certificate_public_key? &&
          valid_credential_public_key?(authenticator_data.credential.public_key) &&
          valid_aaguid?(authenticator_data.attested_credential_data.aaguid) &&
          valid_signature?(authenticator_data, client_data_hash) &&
          [WebAuthn::AttestationStatement::ATTESTATION_TYPE_BASIC_OR_ATTCA, [attestation_certificate]]
      end

      private

      def valid_format?
        !!(raw_attestation_certificates && signature) &&
          raw_attestation_certificates.length == VALID_ATTESTATION_CERTIFICATE_COUNT
      end

      def valid_certificate_public_key?
        certificate_public_key.is_a?(OpenSSL::PKey::EC) &&
          certificate_public_key.group.curve_name == VALID_ATTESTATION_CERTIFICATE_ALGORITHM.key_curve &&
          certificate_public_key.check_key
      end

      def valid_credential_public_key?(public_key_bytes)
        public_key_u2f(public_key_bytes).valid?
      end

      def certificate_public_key
        attestation_certificate.public_key
      end

      def attestation_certificate
        @attestation_certificate ||= OpenSSL::X509::Certificate.new(raw_attestation_certificates[0])
      end

      def valid_aaguid?(attested_credential_data_aaguid)
        attested_credential_data_aaguid == VALID_ATTESTED_AAGUID
      end

      def valid_signature?(authenticator_data, client_data_hash)
        WebAuthn::SignatureVerifier
          .new(VALID_ATTESTATION_CERTIFICATE_ALGORITHM, certificate_public_key)
          .verify(signature, verification_data(authenticator_data, client_data_hash))
      end

      def verification_data(authenticator_data, client_data_hash)
        "\x00" +
          authenticator_data.rp_id_hash +
          client_data_hash +
          authenticator_data.credential.id +
          public_key_u2f(authenticator_data.credential.public_key).to_uncompressed_point
      end

      def public_key_u2f(cose_key_data)
        PublicKey.new(cose_key_data)
      end
    end
  end
end
