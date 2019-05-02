# frozen_string_literal: true

require "openssl"
require "webauthn/authenticator_data/attested_credential_data"
require "webauthn/error"

module WebAuthn
  module AttestationStatement
    class Base
      class NotSupportedError < Error; end

      AAGUID_EXTENSION_OID = "1.3.6.1.4.1.45724.1.1.4"

      def initialize(statement)
        @statement = statement
      end

      def valid?(_authenticator_data, _client_data_hash)
        raise NotImpelementedError
      end

      private

      attr_reader :statement

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

      def attestation_certificate
        attestation_certificate_chain&.first
      end

      def attestation_certificate_chain
        @attestation_certificate_chain ||= raw_attestation_certificates&.map do |raw_certificate|
          OpenSSL::X509::Certificate.new(raw_certificate)
        end
      end

      def algorithm
        statement["alg"]
      end

      def raw_attestation_certificates
        statement["x5c"]
      end

      def raw_ecdaa_key_id
        statement["ecdaaKeyId"]
      end

      def signature
        statement["sig"]
      end
    end
  end
end
