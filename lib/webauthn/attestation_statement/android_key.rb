# frozen_string_literal: true

require "openssl"
require "webauthn/attestation_statement/base"

module WebAuthn
  module AttestationStatement
    class AndroidKey < Base
      EXTENSION_DATA_OID = "1.3.6.1.4.1.11129.2.1.17"

      # https://developer.android.com/training/articles/security-key-attestation#certificate_schema
      ATTESTATION_CHALLENGE_INDEX = 4
      SOFTWARE_ENFORCED_INDEX = 6
      TEE_ENFORCED_INDEX = 7
      PURPOSE_TAG = 1
      ALL_APPLICATIONS_TAG = 600
      ORIGIN_TAG = 702

      # https://android.googlesource.com/platform/hardware/libhardware/+/master/include/hardware/keymaster_defs.h
      KM_ORIGIN_GENERATED = 0
      KM_PURPOSE_SIGN = 2

      def valid?(authenticator_data, client_data_hash)
        valid_signature?(authenticator_data, client_data_hash) &&
          matching_public_key?(authenticator_data) &&
          valid_attestation_challenge?(client_data_hash) &&
          all_applications_field_not_present? &&
          valid_authorization_list_origin? &&
          valid_authorization_list_purpose? &&
          [WebAuthn::AttestationStatement::ATTESTATION_TYPE_BASIC, attestation_certificate_chain]
      end

      private

      def valid_signature?(authenticator_data, client_data_hash)
        attestation_certificate.public_key.verify(
          OpenSSL::Digest::SHA256.new,
          signature,
          authenticator_data.data + client_data_hash
        )
      end

      def matching_public_key?(authenticator_data)
        attestation_certificate.public_key.to_der == authenticator_data.credential.public_key_object.to_der
      end

      def valid_attestation_challenge?(client_data_hash)
        WebAuthn::SecurityUtils.secure_compare(key_description[ATTESTATION_CHALLENGE_INDEX].value, client_data_hash)
      end

      def all_applications_field_not_present?
        tee_enforced.none? { |data| data.tag == ALL_APPLICATIONS_TAG } &&
          software_enforced.none? { |data| data.tag == ALL_APPLICATIONS_TAG }
      end

      def valid_authorization_list_origin?
        tee_enforced.detect { |data| data.tag == ORIGIN_TAG }&.value&.at(0)&.value == KM_ORIGIN_GENERATED ||
          software_enforced.detect { |data| data.tag == ORIGIN_TAG }&.value&.at(0)&.value == KM_ORIGIN_GENERATED
      end

      def valid_authorization_list_purpose?
        tee_enforced.detect { |data| data.tag == PURPOSE_TAG }&.value&.at(0)&.value&.at(0)&.value == KM_PURPOSE_SIGN ||
          software_enforced.detect { |data| data.tag == PURPOSE_TAG }&.value&.at(0)&.value&.at(0)&.value ==
            KM_PURPOSE_SIGN
      end

      def tee_enforced
        key_description[SOFTWARE_ENFORCED_INDEX].value
      end

      def software_enforced
        key_description[TEE_ENFORCED_INDEX].value
      end

      def key_description
        @key_description ||= begin
          extension_data = attestation_certificate.extensions.detect { |ext| ext.oid == EXTENSION_DATA_OID }
          raw_key_description = OpenSSL::ASN1.decode(extension_data).value.last
          OpenSSL::ASN1.decode(raw_key_description.value).value
        end
      end

      def attestation_certificate
        attestation_certificate_chain[0]
      end

      def attestation_certificate_chain
        @attestation_certificate_chain ||= raw_attestation_certificates.map do |cert|
          OpenSSL::X509::Certificate.new(cert)
        end
      end

      def raw_attestation_certificates
        statement["x5c"]
      end

      def signature
        statement["sig"]
      end
    end
  end
end
