# frozen_string_literal: true

require "openssl"
require "webauthn/attestation_statement/base"
require "webauthn/signature_verifier"

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
          valid_certificate_chain? &&
          valid_ec_public_keys?(authenticator_data.credential) &&
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

      def valid_certificate_chain?
        if attestation_certificate_chain
          attestation_certificate_chain[1..-1].all? { |c| certificate_in_use?(c) }
        else
          true
        end
      end

      def valid_ec_public_keys?(credential)
        (attestation_certificate_chain&.map(&:public_key) || [credential.public_key_object])
          .select { |pkey| pkey.is_a?(OpenSSL::PKey::EC) }
          .all? { |pkey| pkey.check_key }
      end

      # Check https://www.w3.org/TR/2018/CR-webauthn-20180807/#packed-attestation-cert-requirements
      def meet_certificate_requirement?
        if attestation_certificate
          subject = attestation_certificate.subject.to_a

          attestation_certificate.version == 2 &&
            certificate_in_use?(attestation_certificate) &&
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

      def certificate_in_use?(certificate)
        now = Time.now

        certificate.not_before < now && now < certificate.not_after
      end

      def valid_signature?(authenticator_data, client_data_hash)
        signature_verifier = WebAuthn::SignatureVerifier.new(
          algorithm,
          attestation_certificate&.public_key || authenticator_data.credential.public_key_object
        )

        signature_verifier.verify(signature, authenticator_data.data + client_data_hash)
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
