# frozen_string_literal: true

require "cbor"
require "uri"
require "openssl"

require "webauthn/authenticator_data"
require "webauthn/authenticator_response"
require "webauthn/attestation_statement"
require "webauthn/client_data"
require "webauthn/encoder"

module WebAuthn
  class AttestationStatementVerificationError < VerificationError; end
  class AttestationTrustworthinessVerificationError < VerificationError; end
  class AttestedCredentialVerificationError < VerificationError; end

  class AuthenticatorAttestationResponse < AuthenticatorResponse
    def self.from_client(response)
      encoder = WebAuthn.configuration.encoder

      new(
        attestation_object: encoder.decode(response["attestationObject"]),
        client_data_json: encoder.decode(response["clientDataJSON"])
      )
    end

    attr_reader :attestation_type, :attestation_trust_path

    def initialize(attestation_object:, **options)
      super(**options)

      @attestation_object = attestation_object
    end

    def verify(expected_challenge, expected_origin = nil, user_verification: nil, rp_id: nil)
      super

      verify_item(:attested_credential)
      if WebAuthn.configuration.verify_attestation_statement
        verify_item(:attestation_statement)
        verify_item(:attestation_trustworthiness) if WebAuthn.configuration.attestation_root_certificates_finders.any?
      end

      true
    end

    def credential
      authenticator_data.credential
    end

    def attestation_statement
      @attestation_statement ||=
        WebAuthn::AttestationStatement.from(attestation["fmt"], attestation["attStmt"])
    end

    def authenticator_data
      @authenticator_data ||= WebAuthn::AuthenticatorData.new(attestation["authData"])
    end

    def attestation_format
      attestation["fmt"]
    end

    def attestation
      @attestation ||= CBOR.decode(attestation_object)
    end

    def aaguid
      raw_aaguid = authenticator_data.attested_credential_data.raw_aaguid
      unless raw_aaguid == WebAuthn::AuthenticatorData::AttestedCredentialData::ZEROED_AAGUID
        authenticator_data.attested_credential_data.aaguid
      end
    end

    def attestation_certificate_key
      raw_subject_key_identifier(attestation_statement.attestation_certificate)&.unpack("H*")&.[](0)
    end

    private

    attr_reader :attestation_object

    def type
      WebAuthn::TYPES[:create]
    end

    def valid_attested_credential?
      authenticator_data.attested_credential_data_included? &&
        authenticator_data.attested_credential_data.valid?
    end

    def valid_attestation_statement?
      @attestation_type, @attestation_trust_path = attestation_statement.valid?(authenticator_data, client_data.hash)
    end

    def valid_attestation_trustworthiness?
      case @attestation_type
      when WebAuthn::AttestationStatement::ATTESTATION_TYPE_NONE
        WebAuthn.configuration.acceptable_attestation_types.include?('None')
      when WebAuthn::AttestationStatement::ATTESTATION_TYPE_SELF
        WebAuthn.configuration.acceptable_attestation_types.include?('Self')
      else
        WebAuthn.configuration.acceptable_attestation_types.include?(@attestation_type) &&
          attestation_root_certificates_store.verify(leaf_certificate, signing_certificates)
      end
    end

    def raw_subject_key_identifier(certificate)
      extension = certificate.extensions.detect { |ext| ext.oid == "subjectKeyIdentifier" }
      return unless extension

      ext_asn1 = OpenSSL::ASN1.decode(extension.to_der)
      ext_value = ext_asn1.value.last
      OpenSSL::ASN1.decode(ext_value.value).value
    end

    def attestation_root_certificates_store
      certificates =
        WebAuthn.configuration.attestation_root_certificates_finders.reduce([]) do |certs, finder|
          if certs.empty?
            finder.find(attestation_format: attestation_format,
                        aaguid: aaguid,
                        attestation_certificate_key_id: attestation_certificate_key) || []
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

    def signing_certificates
      @attestation_trust_path[1..-1]
    end

    def leaf_certificate
      @attestation_trust_path.first
    end
  end
end
