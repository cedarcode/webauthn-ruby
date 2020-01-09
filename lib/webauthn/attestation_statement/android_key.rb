# frozen_string_literal: true

require "android_key_attestation"
require "openssl"
require "webauthn/attestation_statement/base"
require "webauthn/signature_verifier"

module WebAuthn
  module AttestationStatement
    class AndroidKey < Base
      def valid?(authenticator_data, client_data_hash)
        valid_signature?(authenticator_data, client_data_hash) &&
          matching_public_key?(authenticator_data) &&
          valid_attestation_challenge?(client_data_hash) &&
          all_applications_fields_not_set? &&
          valid_authorization_list_origin? &&
          valid_authorization_list_purpose? &&
          [WebAuthn::AttestationStatement::ATTESTATION_TYPE_BASIC, attestation_trust_path]
      end

      def format
        ATTESTATION_FORMAT_ANDROID_KEY
      end

      private

      def valid_signature?(authenticator_data, client_data_hash)
        WebAuthn::SignatureVerifier
          .new(algorithm, attestation_certificate.public_key)
          .verify(signature, authenticator_data.data + client_data_hash)
      end

      def matching_public_key?(authenticator_data)
        attestation_certificate.public_key.to_der == authenticator_data.credential.public_key_object.to_der
      end

      def valid_attestation_challenge?(client_data_hash)
        android_key_attestation.verify_challenge(client_data_hash)
      rescue AndroidKeyAttestation::ChallengeMismatchError
        false
      end

      def all_applications_fields_not_set?
        !tee_enforced.all_applications && !software_enforced.all_applications
      end

      def valid_authorization_list_origin?
        tee_enforced.origin == :generated || software_enforced.origin == :generated
      end

      def valid_authorization_list_purpose?
        tee_enforced.purpose == [:sign] || software_enforced.purpose == [:sign]
      end

      def tee_enforced
        android_key_attestation.tee_enforced
      end

      def software_enforced
        android_key_attestation.software_enforced
      end

      def android_key_attestation
        @android_key_attestation ||= AndroidKeyAttestation::Statement.new(*certificates)
      end
    end
  end
end
