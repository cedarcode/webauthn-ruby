# frozen_string_literal: true

require "cose/algorithm"
require "openssl"
require "webauthn/attestation_statement/base"
require "webauthn/attestation_statement/tpm/cert_info"
require "webauthn/attestation_statement/tpm/pub_area"
require "webauthn/signature_verifier"

module WebAuthn
  module AttestationStatement
    class TPM < Base
      CERTIFICATE_V3 = 2
      CERTIFICATE_EMPTY_NAME = OpenSSL::X509::Name.new([]).freeze
      OID_TCG_KP_AIK_CERTIFICATE = "2.23.133.8.3"
      TPM_V2 = "2.0"

      def valid?(authenticator_data, client_data_hash)
        case attestation_type
        when ATTESTATION_TYPE_ATTCA
          att_to_be_signed = authenticator_data.data + client_data_hash

          ver == TPM_V2 &&
            valid_signature? &&
            valid_aik_certificate? &&
            pub_area.valid?(authenticator_data.credential.public_key, alg) &&
            cert_info.valid?(pub_area.valid_name, OpenSSL::Digest.digest(algorithm.hash, att_to_be_signed)) &&
            matching_aaguid?(authenticator_data.attested_credential_data.aaguid) &&
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
        WebAuthn::SignatureVerifier.new(alg, aik_certificate.public_key).verify(sig, verification_data)
      end

      def valid_aik_certificate?
        aik_certificate.version == CERTIFICATE_V3 &&
          aik_certificate.subject.eql?(CERTIFICATE_EMPTY_NAME) &&
          certificate_in_use?(aik_certificate) &&
          aik_certificate.extensions.find { |ext| ext.oid == 'basicConstraints' }&.value == "CA:FALSE" &&
          aik_certificate.extensions.find { |ext| ext.oid == "extendedKeyUsage" }&.value == OID_TCG_KP_AIK_CERTIFICATE
      end

      def certificate_in_use?(certificate)
        now = Time.now

        certificate.not_before < now && now < certificate.not_after
      end

      def verification_data
        statement["certInfo"]
      end

      def aik_certificate
        attestation_certificate_chain[0]
      end

      alias_method :attestation_certificate, :aik_certificate

      def cert_info
        @cert_info ||= CertInfo.new(statement["certInfo"])
      end

      def pub_area
        @pub_area ||= PubArea.new(statement["pubArea"])
      end

      def attestation_certificate_chain
        @attestation_certificate_chain ||= raw_certificates.map { |c| OpenSSL::X509::Certificate.new(c) }
      end

      def raw_certificates
        statement["x5c"]
      end

      def sig
        statement["sig"]
      end

      def ver
        statement["ver"]
      end

      def algorithm
        @algorithm ||= COSE::Algorithm.find(alg)
      end

      def alg
        statement["alg"]
      end

      def ecdaa_key_id
        statement["ecdaaKeyId"]
      end

      def attestation_type
        if raw_certificates && !ecdaa_key_id
          ATTESTATION_TYPE_ATTCA
        elsif ecdaa_key_id && !raw_certificates
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
