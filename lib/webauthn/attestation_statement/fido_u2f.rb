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

      def valid?(authenticator_data, client_data_hash)
        valid_format? &&
          valid_certificate_public_key? &&
          valid_credential_public_key?(authenticator_data.credential.public_key) &&
          valid_aaguid?(authenticator_data.attested_credential_data.raw_aaguid) &&
          valid_signature?(authenticator_data, client_data_hash) &&
          certificate_chain_trusted? &&
          [WebAuthn::AttestationStatement::ATTESTATION_TYPE_BASIC_OR_ATTCA, [attestation_certificate]]
      end

      def attestation_certificate_key_id
        return @attestation_certificate_key_id if defined?(@attestation_certificate_key_id)

        @attestation_certificate_key_id = begin
          extension = attestation_certificate.extensions.detect { |ext| ext.oid == "subjectKeyIdentifier" }
          return if extension.nil? || extension.critical?

          sequence = OpenSSL::ASN1.decode(extension.to_der)
          octet_string = sequence.detect do |value|
            value.tag_class == :UNIVERSAL && value.tag == OpenSSL::ASN1::OCTET_STRING
          end
          return unless octet_string

          OpenSSL::ASN1.decode(octet_string.value).value.unpack("H*")[0]
        end
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

      def valid_aaguid?(attested_credential_data_aaguid)
        attested_credential_data_aaguid == WebAuthn::AuthenticatorData::AttestedCredentialData::ZEROED_AAGUID
      end

      def valid_signature?(authenticator_data, client_data_hash)
        WebAuthn::SignatureVerifier
          .new(VALID_ATTESTATION_CERTIFICATE_ALGORITHM, certificate_public_key)
          .verify(signature, verification_data(authenticator_data, client_data_hash))
      end

      def certificate_chain_trusted?
        find_metadata
        return false unless metadata_statement

        trust_store = build_trust_store(metadata_statement.attestation_root_certificates)
        trust_store.verify(attestation_certificate, attestation_certificate_chain[1..-1])
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

      def find_metadata
        key_id = attestation_certificate_key_id
        return unless key_id

        @metadata_entry = metadata_store.fetch_entry(attestation_certificate_key_id: key_id)
        @metadata_statement = metadata_store.fetch_statement(attestation_certificate_key_id: key_id)
      end
    end
  end
end
