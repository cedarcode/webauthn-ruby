# frozen_string_literal: true

require "cose/algorithm"
require "openssl"
require "tpm/key_attestation"
require "webauthn/attestation_statement/base"
require "webauthn/signature_verifier"

module WebAuthn
  module AttestationStatement
    class TPM < Base
      TPM_V2 = "2.0"

      COSE_ALG_TO_TPM = {
        "RS1" => { signature: ::TPM::ALG_RSASSA, hash: ::TPM::ALG_SHA1 },
        "RS256" => { signature: ::TPM::ALG_RSASSA, hash: ::TPM::ALG_SHA256 },
        "PS256" => { signature: ::TPM::ALG_RSAPSS, hash: ::TPM::ALG_SHA256 },
        "ES256" => { signature: ::TPM::ALG_ECDSA, hash: ::TPM::ALG_SHA256 },
      }.freeze

      def valid?(authenticator_data, client_data_hash)
        case attestation_type
        when ATTESTATION_TYPE_ATTCA
          ver == TPM_V2 &&
            valid_key_attestation?(
              authenticator_data.data + client_data_hash,
              authenticator_data.credential.public_key_object,
              authenticator_data.aaguid
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

      def valid_key_attestation?(certified_extra_data, key, aaguid)
        key_attestation =
          ::TPM::KeyAttestation.new(
            statement["certInfo"],
            signature,
            statement["pubArea"],
            certificates,
            OpenSSL::Digest.digest(cose_algorithm.hash_function, certified_extra_data),
            signature_algorithm: tpm_algorithm[:signature],
            hash_algorithm: tpm_algorithm[:hash],
            root_certificates: root_certificates(aaguid: aaguid)
          )

        key_attestation.valid? && key_attestation.key && key_attestation.key.to_pem == key.to_pem
      end

      def root_certificates(aaguid: nil, attestation_certificate_key_id: nil)
        certs = super

        if certs.empty?
          ::TPM::KeyAttestation::ROOT_CERTIFICATES
        else
          certs
        end
      end

      def tpm_algorithm
        COSE_ALG_TO_TPM[cose_algorithm.name] || raise("Unsupported algorithm #{cose_algorithm.name}")
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
    end
  end
end
