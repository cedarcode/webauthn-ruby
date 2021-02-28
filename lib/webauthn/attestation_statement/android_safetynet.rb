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
          trustworthy?(aaguid: authenticator_data.aaguid) &&
          [attestation_type, attestation_trust_path]
      end

      private

      def valid_response?(authenticator_data, client_data_hash)
        nonce = Digest::SHA256.base64digest(authenticator_data.data + client_data_hash)

        begin
          attestation_response
            .verify(nonce, trusted_certificates: root_certificates(aaguid: authenticator_data.aaguid), time: time)
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

      def valid_certificate_chain?(**_)
        # Already performed as part of #valid_response?
        true
      end

      def attestation_type
        WebAuthn::AttestationStatement::ATTESTATION_TYPE_BASIC
      end

      # SafetyNetAttestation returns full chain including root, WebAuthn expects only the x5c certificates
      def certificates
        attestation_response.certificate_chain[0..-2]
      end

      def attestation_response
        @attestation_response ||= SafetyNetAttestation::Statement.new(statement["response"])
      end

      def default_root_certificates
        SafetyNetAttestation::Statement::GOOGLE_ROOT_CERTIFICATES
      end

      def time
        Time.now
      end
    end
  end
end
