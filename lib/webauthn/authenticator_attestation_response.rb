# frozen_string_literal: true

require "cbor"
require "uri"
require "openssl"

require "webauthn/authenticator_data"
require "webauthn/authenticator_response"
require "webauthn/attestation_statement"
require "webauthn/client_data"

module WebAuthn
  class AttestationStatementVerificationError < VerificationError; end

  class AuthenticatorAttestationResponse < AuthenticatorResponse
    attr_reader :attestation_type, :attestation_trust_path

    def initialize(attestation_object:, **options)
      super(options)

      @attestation_object = attestation_object
    end

    def verify(expected_challenge, expected_origin = nil, user_verification: nil, rp_id: nil)
      super

      verify_item(:attestation_statement) if WebAuthn.configuration.verify_attestation_statement

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

    def valid_attestation_statement?
      @attestation_type, @attestation_trust_path = attestation_statement.valid?(authenticator_data, client_data.hash)
    end

    def raw_subject_key_identifier(certificate)
      extension = certificate.extensions.detect { |ext| ext.oid == "subjectKeyIdentifier" }
      return unless extension

      ext_asn1 = OpenSSL::ASN1.decode(extension.to_der)
      ext_value = ext_asn1.value.last
      OpenSSL::ASN1.decode(ext_value.value).value
    end
  end
end
