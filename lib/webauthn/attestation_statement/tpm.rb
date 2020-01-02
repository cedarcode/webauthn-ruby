# frozen_string_literal: true

require "cose/algorithm"
require "openssl"
require "tpm/ek_certificate"
require "webauthn/attestation_statement/base"
require "webauthn/attestation_statement/tpm/cert_info"
require "webauthn/attestation_statement/tpm/pub_area"
require "webauthn/signature_verifier"

module WebAuthn
  module AttestationStatement
    class TPM < Base
      TPM_V2 = "2.0"

      def valid?(authenticator_data, client_data_hash)
        case attestation_type
        when ATTESTATION_TYPE_ATTCA
          att_to_be_signed = authenticator_data.data + client_data_hash

          ver == TPM_V2 &&
            valid_signature? &&
            valid_attestation_certificate? &&
            pub_area.valid?(authenticator_data.credential.public_key) &&
            cert_info.valid?(
              statement["pubArea"],
              OpenSSL::Digest.digest(cose_algorithm.hash_function, att_to_be_signed)
            ) &&
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
        ek_certificate.conformant? && ek_certificate.empty_subject?
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
        if raw_certificates && !raw_ecdaa_key_id
          ATTESTATION_TYPE_ATTCA
        elsif raw_ecdaa_key_id && !raw_certificates
          ATTESTATION_TYPE_ECDAA
        else
          raise "Attestation type invalid"
        end
      end

      def ek_certificate
        @ek_certificate ||= ::TPM::EKCertificate.from_der(raw_certificates.first)
      end
    end
  end
end
