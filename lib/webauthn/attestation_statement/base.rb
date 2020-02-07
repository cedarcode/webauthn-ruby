# frozen_string_literal: true

require "openssl"
require "webauthn/authenticator_data/attested_credential_data"
require "webauthn/error"

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

      def initialize(statement)
        @statement = statement
      end

      def valid?(_authenticator_data, _client_data_hash)
        raise NotImplementedError
      end

      def format
        WebAuthn::AttestationStatement::FORMAT_TO_CLASS.key(self.class)
      end

      def attestation_certificate
        certificates&.first
      end

      def certificate_chain
        if certificates
          certificates[1..-1]
        end
      end

      def attestation_certificate_key_id
        raw_subject_key_identifier&.unpack("H*")&.[](0)
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

      def certificates
        @certificates ||=
          raw_certificates&.map do |raw_certificate|
            OpenSSL::X509::Certificate.new(raw_certificate)
          end
      end

      def algorithm
        statement["alg"]
      end

      def raw_certificates
        statement["x5c"]
      end

      def raw_ecdaa_key_id
        statement["ecdaaKeyId"]
      end

      def signature
        statement["sig"]
      end

      def attestation_trust_path
        if certificates&.any?
          certificates
        end
      end

      def valid_certificate_chain?(attestation_type, aaguid: nil, attestation_certificate_key_id: nil)
        case attestation_type
        when WebAuthn::AttestationStatement::ATTESTATION_TYPE_NONE
          WebAuthn.configuration.acceptable_attestation_types.include?('None')
        when WebAuthn::AttestationStatement::ATTESTATION_TYPE_SELF
          WebAuthn.configuration.acceptable_attestation_types.include?('Self')
        else
          WebAuthn.configuration.acceptable_attestation_types.include?(attestation_type) &&
            attestation_root_certificates_store(
              aaguid: aaguid,
              attestation_certificate_key_id: attestation_certificate_key_id
            ).verify(attestation_certificate, attestation_trust_path)
        end
      end

      def attestation_root_certificates_store(aaguid: nil, attestation_certificate_key_id: nil)
        certificates =
          WebAuthn.configuration.attestation_root_certificates_finders.reduce([]) do |certs, finder|
            if certs.empty?
              finder.find(
                attestation_format: format,
                aaguid: aaguid,
                attestation_certificate_key_id: attestation_certificate_key_id
              ) || []
            else
              certs
            end
          end

        OpenSSL::X509::Store.new.tap do |store|
          certificates.each do |cert|
            store.add_cert(cert)
          end
        end
      end

      def raw_subject_key_identifier
        extension = attestation_certificate.extensions.detect { |ext| ext.oid == "subjectKeyIdentifier" }
        return unless extension

        ext_asn1 = OpenSSL::ASN1.decode(extension.to_der)
        ext_value = ext_asn1.value.last
        OpenSSL::ASN1.decode(ext_value.value).value
      end
    end
  end
end
