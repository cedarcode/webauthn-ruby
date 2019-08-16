# frozen_string_literal: true

require "android_safetynet/attestation_response"
require "openssl"
require "webauthn/attestation_statement/base"

module WebAuthn
  module AttestationStatement
    # Implements https://www.w3.org/TR/webauthn-1/#sctn-android-safetynet-attestation
    class AndroidSafetynet < Base
      def self.default_trust_store
        OpenSSL::X509::Store.new.tap { |trust_store| trust_store.set_default_paths }
      end

      def valid?(authenticator_data, client_data_hash, trust_store: self.class.default_trust_store)
        trusted_attestation_certificate?(trust_store) &&
          valid_response?(authenticator_data, client_data_hash) &&
          valid_version? &&
          cts_profile_match? &&
          [WebAuthn::AttestationStatement::ATTESTATION_TYPE_BASIC, attestation_certificate]
      end

      def attestation_certificate
        attestation_response.certificate_chain[0]
      end

      private

      # FIXME: This should be a responsibility of AndroidSafetynet::AttestationResponse#verify
      def trusted_attestation_certificate?(trust_store)
        trust_store.verify(attestation_certificate, signing_certificates)
      end

      def valid_response?(authenticator_data, client_data_hash)
        nonce = Digest::SHA256.base64digest(authenticator_data.data + client_data_hash)

        begin
          attestation_response.verify(nonce)
        rescue ::AndroidSafetynet::AttestationResponse::VerificationError
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

      def signing_certificates
        attestation_response.certificate_chain[1..-1]
      end

      def attestation_response
        @attestation_response ||= ::AndroidSafetynet::AttestationResponse.new(statement["response"])
      end
    end
  end
end
