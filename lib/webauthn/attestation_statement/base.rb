# frozen_string_literal: true

require "openssl"
require "webauthn/authenticator_data/attested_credential_data"
require "webauthn/error"
require "webauthn/metadata/store"

module WebAuthn
  module AttestationStatement
    ATTESTATION_TYPE_NONE = "None"
    ATTESTATION_TYPE_BASIC = "Basic"
    ATTESTATION_TYPE_SELF = "Self"
    ATTESTATION_TYPE_ATTCA = "AttCA"
    ATTESTATION_TYPE_ECDAA = "ECDAA"
    ATTESTATION_TYPE_BASIC_OR_ATTCA = "Basic_or_AttCA"

    class Base
      class NotSupportedError < Error; end

      AAGUID_EXTENSION_OID = "1.3.6.1.4.1.45724.1.1.4"

      attr_reader :metadata_entry, :metadata_statement

      def initialize(statement)
        @statement = statement
      end

      def valid?(_authenticator_data, _client_data_hash)
        raise NotImpelementedError
      end

      def attestation_certificate
        attestation_certificate_chain&.first
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

      def metadata_store
        @metadata_store ||= WebAuthn::Metadata::Store.new
      end

      def find_metadata(aaguid)
        @metadata_entry = metadata_store.fetch_entry(aaguid: aaguid)
        @metadata_statement = metadata_store.fetch_statement(aaguid: aaguid)
      end

      def build_trust_store(root_certificates)
        trust_store = OpenSSL::X509::Store.new
        root_certificates.each do |certificate|
          trust_store.add_cert(certificate)
        end
        trust_store
      end
    end
  end
end
