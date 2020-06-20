# frozen_string_literal: true

require "cose"
require "openssl"
require "webauthn/attestation_statement/base"
require "webauthn/attestation_statement/fido_u2f/public_key"

module WebAuthn
  module AttestationStatement
    class FidoU2f < Base
      VALID_ATTESTATION_CERTIFICATE_COUNT = 1
      VALID_ATTESTATION_CERTIFICATE_ALGORITHM = COSE::Algorithm.by_name("ES256")
      VALID_ATTESTATION_CERTIFICATE_KEY_CURVE = COSE::Key::Curve.by_name("P-256")

      def valid?(authenticator_data, client_data_hash)
        valid_format? &&
          valid_certificate_public_key? &&
          valid_credential_public_key?(authenticator_data.credential.public_key) &&
          valid_aaguid?(authenticator_data.attested_credential_data.raw_aaguid) &&
          valid_signature?(authenticator_data, client_data_hash) &&
          trustworthy?(attestation_certificate_key_id: attestation_certificate_key_id) &&
          [attestation_type, attestation_trust_path]
      end

      private

      def valid_format?
        !!(raw_certificates && signature) &&
          raw_certificates.length == VALID_ATTESTATION_CERTIFICATE_COUNT
      end

      def valid_certificate_public_key?
        certificate_public_key.is_a?(OpenSSL::PKey::EC) &&
          certificate_public_key.group.curve_name == VALID_ATTESTATION_CERTIFICATE_KEY_CURVE.pkey_name &&
          certificate_public_key.check_key
      end

      def valid_credential_public_key?(public_key_bytes)
        public_key_u2f(public_key_bytes).valid?
      end

      def certificate_public_key
        attestation_certificate.public_key
      end

      def valid_aaguid?(attested_credential_data_aaguid)
        attested_credential_data_aaguid == WebAuthn::AuthenticatorData::AttestedCredentialData::ZEROED_AAGUID
      end

      def algorithm
        VALID_ATTESTATION_CERTIFICATE_ALGORITHM.id
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

      def attestation_type
        WebAuthn::AttestationStatement::ATTESTATION_TYPE_BASIC_OR_ATTCA
      end
    end
  end
end
