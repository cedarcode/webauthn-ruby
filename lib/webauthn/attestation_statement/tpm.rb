# frozen_string_literal: true

require "cose/algorithm"
require "openssl"
require "tpm/constants"
require "webauthn/attestation_statement/base"
require "webauthn/attestation_statement/tpm/cert_info"
require "webauthn/attestation_statement/tpm/pub_area"
require "webauthn/signature_verifier"

module WebAuthn
  module AttestationStatement
    class TPM < Base
      CERTIFICATE_V3 = 2
      CERTIFICATE_EMPTY_NAME = OpenSSL::X509::Name.new([]).freeze
      CERTIFICATE_SAN_DIRECTORY_NAME = 4
      OID_TCG_AT_TPM_MANUFACTURER = "2.23.133.2.1"
      OID_TCG_AT_TPM_MODEL = "2.23.133.2.2"
      OID_TCG_AT_TPM_VERSION = "2.23.133.2.3"
      OID_TCG_KP_AIK_CERTIFICATE = "2.23.133.8.3"
      TPM_V2 = "2.0"

      def valid?(authenticator_data, client_data_hash)
        case attestation_type
        when ATTESTATION_TYPE_ATTCA
          att_to_be_signed = authenticator_data.data + client_data_hash

          ver == TPM_V2 &&
            valid_signature? &&
            valid_attestation_certificate? &&
            pub_area.valid?(authenticator_data.credential.public_key) &&
            cert_info.valid?(statement["pubArea"], OpenSSL::Digest.digest(cose_algorithm.hash, att_to_be_signed)) &&
            matching_aaguid?(authenticator_data.attested_credential_data.raw_aaguid) &&
            [attestation_type, attestation_trust_path]
        when ATTESTATION_TYPE_ECDAA
          raise(
            WebAuthn::AttestationStatement::Base::NotSupportedError,
            "Attestation type ECDAA is not supported"
          )
        end
      end

      private

      def valid_signature?
        WebAuthn::SignatureVerifier
          .new(algorithm, attestation_certificate.public_key)
          .verify(signature, verification_data, rsa_pss_salt_length: :auto)
      end

      def valid_attestation_certificate?
        extensions = attestation_certificate.extensions

        attestation_certificate.version == CERTIFICATE_V3 &&
          attestation_certificate.subject.eql?(CERTIFICATE_EMPTY_NAME) &&
          valid_subject_alternative_name? &&
          certificate_in_use?(attestation_certificate) &&
          extensions.find { |ext| ext.oid == 'basicConstraints' }&.value == "CA:FALSE" &&
          extensions.find { |ext| ext.oid == "extendedKeyUsage" }&.value == OID_TCG_KP_AIK_CERTIFICATE
      end

      def valid_subject_alternative_name?
        extension = attestation_certificate.extensions.detect { |ext| ext.oid == "subjectAltName" }
        return unless extension&.critical?

        san_asn1 = OpenSSL::ASN1.decode(extension).find do |val|
          val.tag_class == :UNIVERSAL && val.tag == OpenSSL::ASN1::OCTET_STRING
        end
        directory_name = OpenSSL::ASN1.decode(san_asn1.value).find do |val|
          val.tag_class == :CONTEXT_SPECIFIC && val.tag == CERTIFICATE_SAN_DIRECTORY_NAME
        end
        name = OpenSSL::X509::Name.new(directory_name.value.first).to_a
        manufacturer = name.assoc(OID_TCG_AT_TPM_MANUFACTURER).at(1)
        model = name.assoc(OID_TCG_AT_TPM_MODEL).at(1)
        version = name.assoc(OID_TCG_AT_TPM_VERSION).at(1)

        ::TPM::VENDOR_IDS[manufacturer] && !model.empty? && !version.empty?
      end

      def certificate_in_use?(certificate)
        now = Time.now

        certificate.not_before < now && now < certificate.not_after
      end

      def verification_data
        statement["certInfo"]
      end

      def cert_info
        @cert_info ||= CertInfo.new(statement["certInfo"])
      end

      def pub_area
        @pub_area ||= PubArea.new(statement["pubArea"])
      end

      def ver
        statement["ver"]
      end

      def cose_algorithm
        @cose_algorithm ||= COSE::Algorithm.find(algorithm)
      end

      def attestation_type
        if raw_attestation_certificates && !raw_ecdaa_key_id
          ATTESTATION_TYPE_ATTCA
        elsif raw_ecdaa_key_id && !raw_attestation_certificates
          ATTESTATION_TYPE_ECDAA
        else
          raise "Attestation type invalid"
        end
      end

      def attestation_trust_path
        attestation_certificate_chain
      end
    end
  end
end
