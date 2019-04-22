# frozen_string_literal: true

require "openssl"
require "webauthn/attestation_statement/android_key/key_description"
require "webauthn/attestation_statement/base"
require "webauthn/signature_verifier"

module WebAuthn
  module AttestationStatement
    class AndroidKey < Base
      EXTENSION_DATA_OID = "1.3.6.1.4.1.11129.2.1.17"

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
        WebAuthn::SignatureVerifier
          .new(algorithm, attestation_certificate.public_key)
          .verify(signature, authenticator_data.data + client_data_hash)
      end

      def matching_public_key?(authenticator_data)
        attestation_certificate.public_key.to_der == authenticator_data.credential.public_key_object.to_der
      end

      def valid_attestation_challenge?(client_data_hash)
        WebAuthn::SecurityUtils.secure_compare(key_description.attestation_challenge, client_data_hash)
      end

      def all_applications_field_not_present?
        tee_enforced.all_applications.nil? && software_enforced.all_applications.nil?
      end

      def valid_authorization_list_origin?
        tee_enforced.origin == KM_ORIGIN_GENERATED || software_enforced.origin == KM_ORIGIN_GENERATED
      end

      def valid_authorization_list_purpose?
        tee_enforced.purpose == KM_PURPOSE_SIGN || software_enforced.purpose == KM_PURPOSE_SIGN
      end

      def tee_enforced
        key_description.tee_enforced
      end

      def software_enforced
        key_description.software_enforced
      end

      def key_description
        @key_description ||= begin
          extension_data = attestation_certificate.extensions.detect { |ext| ext.oid == EXTENSION_DATA_OID }
          raw_key_description = OpenSSL::ASN1.decode(extension_data).value.last

          KeyDescription.new(OpenSSL::ASN1.decode(raw_key_description.value).value)
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
    end
  end
end
