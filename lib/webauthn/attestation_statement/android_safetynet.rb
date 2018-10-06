# frozen_string_literal: true

require "jwt"
require "openssl"
require "webauthn/attestation_statement/base"

module WebAuthn
  module AttestationStatement
    # Implements https://www.w3.org/TR/2018/CR-webauthn-20180807/#android-safetynet-attestation
    class AndroidSafetynet < Base
      def self.default_trust_store
        OpenSSL::X509::Store.new.tap { |trust_store| trust_store.set_default_paths }
      end

      def valid?(authenticator_data, client_data_hash, trust_store: self.class.default_trust_store)
        trusted_attestation_certificate?(trust_store) &&
          valid_signature? &&
          valid_attestation_domain? &&
          valid_version? &&
          valid_nonce?(authenticator_data, client_data_hash) &&
          cts_profile_match?
      end

      private

      def trusted_attestation_certificate?(trust_store)
        signing_certificates.each do |certificate|
          trust_store.add_cert(certificate)
        end
        trust_store.verify(attestation_certificate)
      end

      def valid_signature?
        signed_payload, _, base64_signature = statement["response"].rpartition(".")
        signature = Base64.urlsafe_decode64(base64_signature)
        attestation_certificate.public_key.verify(OpenSSL::Digest::SHA256.new, signature, signed_payload)
      end

      def valid_attestation_domain?
        subject = attestation_certificate.subject.to_a
        subject.assoc('CN')[1] == "attest.android.com"
      end

      # TODO: improve once the spec has clarifications https://github.com/w3c/webauthn/issues/968
      def valid_version?
        !statement["ver"].empty?
      end

      def valid_nonce?(authenticator_data, client_data_hash)
        nonce = unverified_jws_result[0]["nonce"]
        nonce == verification_data(authenticator_data, client_data_hash)
      end

      def cts_profile_match?
        unverified_jws_result[0]["ctsProfileMatch"]
      end

      def verification_data(authenticator_data, client_data_hash)
        Digest::SHA256.base64digest(authenticator_data.data + client_data_hash)
      end

      def attestation_certificate
        attestation_certificate_chain[0]
      end

      def signing_certificates
        attestation_certificate_chain[1..-1]
      end

      def attestation_certificate_chain
        @attestation_certificate_chain ||= unverified_jws_result[1]["x5c"].map do |cert|
          OpenSSL::X509::Certificate.new(Base64.strict_decode64(cert))
        end
      end

      def unverified_jws_result
        @unverified_jws_result ||= JWT.decode(statement["response"], nil, false)
      end
    end
  end
end
