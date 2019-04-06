# frozen_string_literal: true

require "cose/algorithm"
require "openssl"
require "webauthn/attestation_statement/base"

module WebAuthn
  # Implements https://www.w3.org/TR/2018/CR-webauthn-20180807/#packed-attestation
  # ECDAA attestation is unsupported.
  module AttestationStatement
    class Packed < Base
      # Follows "Verification procedure"
      def valid?(authenticator_data, client_data_hash)
        check_unsupported_feature

        valid_format? &&
          valid_algorithm?(authenticator_data.credential) &&
          valid_certificate_chain?(authenticator_data.credential) &&
          meet_certificate_requirement? &&
          matching_aaguid?(authenticator_data.attested_credential_data.aaguid) &&
          valid_signature?(authenticator_data, client_data_hash) &&
          attestation_type_and_trust_path
      end

      private

      def valid_algorithm?(credential)
        !self_attestation? || algorithm == COSE::Key.deserialize(credential.public_key).alg
      end

      def self_attestation?
        !raw_attestation_certificates && !raw_ecdaa_key_id
      end

      def algorithm
        statement["alg"]
      end

      def signature
        statement["sig"]
      end

      def raw_attestation_certificates
        statement["x5c"]
      end

      def raw_ecdaa_key_id
        statement["ecdaaKeyId"]
      end

      def valid_format?
        algorithm && signature && (
          [raw_attestation_certificates, raw_ecdaa_key_id].compact.size < 2
        )
      end

      def check_unsupported_feature
        if raw_ecdaa_key_id
          raise NotSupportedError, "ecdaaKeyId of the packed attestation format is not implemented yet"
        end
      end

      def attestation_certificate_chain
        @attestation_certificate_chain ||= raw_attestation_certificates&.map do |cert|
          OpenSSL::X509::Certificate.new(cert)
        end
      end

      def attestation_certificate
        attestation_certificate_chain&.first
      end

      def valid_certificate_chain?(credential)
        public_keys = attestation_certificate_chain&.map(&:public_key) || [credential.public_key_object]
        public_keys.all? do |public_key|
          public_key.is_a?(OpenSSL::PKey::EC) && public_key.check_key
        end
      end

      # Check https://www.w3.org/TR/2018/CR-webauthn-20180807/#packed-attestation-cert-requirements
      def meet_certificate_requirement?
        if attestation_certificate
          subject = attestation_certificate.subject.to_a

          attestation_certificate.version == 2 &&
            attestation_certificate.not_before < Time.now &&
            attestation_certificate.not_after > Time.now &&
            subject.assoc('OU')&.at(1) == "Authenticator Attestation" &&
            attestation_certificate.extensions.find { |ext| ext.oid == 'basicConstraints' }&.value == 'CA:FALSE'
        else
          true
        end
      end

      def matching_aaguid?(attested_credential_data_aaguid)
        extension = attestation_certificate&.extensions&.detect { |ext| ext.oid == AAGUID_EXTENSION_OID }
        if extension
          # `extension.value` mangles data into ASCII, so we must manually compare bytes
          # see https://github.com/ruby/openssl/pull/234
          extension.to_der[-WebAuthn::AuthenticatorData::AttestedCredentialData::AAGUID_LENGTH..-1] ==
            attested_credential_data_aaguid
        else
          true
        end
      end

      def valid_signature?(authenticator_data, client_data_hash)
        cose_algorithm = COSE::Algorithm.find(algorithm)

        if cose_algorithm
          (attestation_certificate&.public_key || authenticator_data.credential.public_key_object).verify(
            cose_algorithm.hash,
            signature,
            verification_data(authenticator_data, client_data_hash)
          )
        else
          raise "Unsupported algorithm #{algorithm}"
        end
      end

      def verification_data(authenticator_data, client_data_hash)
        authenticator_data.data + client_data_hash
      end

      def attestation_type_and_trust_path
        if raw_attestation_certificates&.any?
          [WebAuthn::AttestationStatement::ATTESTATION_TYPE_BASIC_OR_ATTCA, attestation_certificate_chain]
        else
          [WebAuthn::AttestationStatement::ATTESTATION_TYPE_SELF, nil]
        end
      end
    end
  end
end
