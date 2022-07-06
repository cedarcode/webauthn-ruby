# frozen_string_literal: true

require "cose/algorithm"
require "openssl"
require "tpm/key_attestation"
require "webauthn/attestation_statement/base"

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
        attestation_type == ATTESTATION_TYPE_ATTCA &&
          ver == TPM_V2 &&
          valid_key_attestation?(
            authenticator_data.data + client_data_hash,
            authenticator_data.credential.public_key_object,
            authenticator_data.aaguid
          ) &&
          matching_aaguid?(authenticator_data.attested_credential_data.raw_aaguid) &&
          trustworthy?(aaguid: authenticator_data.aaguid) &&
          [attestation_type, attestation_trust_path]
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
            trusted_certificates: root_certificates(aaguid: aaguid)
          )

        key_attestation.valid? && key_attestation.key && key_attestation.key.to_pem == key.to_pem
      end

      def valid_certificate_chain?(**_)
        # Already performed as part of #valid_key_attestation?
        true
      end

      def default_root_certificates
        ::TPM::KeyAttestation::TRUSTED_CERTIFICATES
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
        if raw_certificates
          ATTESTATION_TYPE_ATTCA
        else
          raise "Attestation type invalid"
        end
      end
    end
  end
end
