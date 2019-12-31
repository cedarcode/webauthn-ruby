# frozen_string_literal: true

require "safety_net_attestation"
require "openssl"
require "webauthn/attestation_statement/base"

module WebAuthn
  module AttestationStatement
    # Implements https://www.w3.org/TR/webauthn-1/#sctn-android-safetynet-attestation
    class AndroidSafetynet < Base
      def valid?(authenticator_data, client_data_hash)
        valid_response?(authenticator_data, client_data_hash) &&
          valid_version? &&
          cts_profile_match? &&
          [WebAuthn::AttestationStatement::ATTESTATION_TYPE_BASIC, attestation_trust_path]
      end

      def attestation_certificate
        attestation_trust_path.first
      end

      private

      def valid_response?(authenticator_data, client_data_hash)
        nonce = Digest::SHA256.base64digest(authenticator_data.data + client_data_hash)

        begin
          attestation_response.verify(nonce, trusted_certificates: attestation_root_certificates, time: time)
        rescue SafetyNetAttestation::Error
          false
        end
      end

      # TODO: improve once the spec has clarifications https://github.com/w3c/webauthn/issues/968
      def valid_version?
        !statement["ver"].empty?
      end

      def cts_profile_match?
        attestation_response.cts_profile_match?
      end

      # SafetyNetAttestation returns full chain including root, WebAuthn expects only the x5c certificates
      def attestation_trust_path
        attestation_response.certificate_chain[0..-2]
      end

      def attestation_response
        @attestation_response ||= SafetyNetAttestation::Statement.new(statement["response"])
      end

      def attestation_root_certificates
        SafetyNetAttestation::Statement::GOOGLE_ROOT_CERTIFICATES
      end

      def time
        Time.now
      end
    end
  end
end
