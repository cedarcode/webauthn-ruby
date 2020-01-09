# frozen_string_literal: true

require "cbor"
require "openssl"
require "webauthn/attestation_statement"
require "webauthn/authenticator_data"

module WebAuthn
  class Attestation
    def self.deserialize(attestation_object)
      from_map(CBOR.decode(attestation_object))
    end

    def self.from_map(map)
      new(
        authenticator_data: WebAuthn::AuthenticatorData.new(map["authData"]),
        attestation_statement: WebAuthn::AttestationStatement.from(map["fmt"], map["attStmt"])
      )
    end

    attr_reader :authenticator_data, :attestation_statement

    def initialize(authenticator_data:, attestation_statement:)
      @authenticator_data = authenticator_data
      @attestation_statement = attestation_statement
    end

    def valid_attested_credential?
      authenticator_data.attested_credential_data_included? &&
        authenticator_data.attested_credential_data.valid?
    end

    def valid_attestation_statement?(client_data_hash)
      @type, @trust_path = attestation_statement.valid?(authenticator_data, client_data_hash)
    end

    def trustworthy?
      case type
      when WebAuthn::AttestationStatement::ATTESTATION_TYPE_NONE
        acceptable_types.include?('None')
      when WebAuthn::AttestationStatement::ATTESTATION_TYPE_SELF
        acceptable_types.include?('Self')
      else
        acceptable_types.include?(type) && root_store.verify(subject_certificate, intermediate_certificates)
      end
    end

    def aaguid
      authenticator_data.aaguid
    end

    def certificate_key_id
      attestation_statement.certificate_key_id
    end

    private

    attr_reader :type, :trust_path

    def acceptable_types
      configuration.acceptable_attestation_types
    end

    def subject_certificate
      trust_path[0]
    end

    def intermediate_certificates
      trust_path[1..-1]
    end

    def root_store
      @root_store ||=
        OpenSSL::X509::Store.new.tap do |store|
          root_certificates.each do |certificate|
            store.add_cert(certificate)
          end
        end
    end

    def root_certificates
      configuration.attestation_root_certificates_finders.reduce([]) do |certs, finder|
        if certs.empty?
          finder.find(
            attestation_format: attestation_statement.format,
            aaguid: aaguid,
            attestation_certificate_key_id: certificate_key_id
          ) || []
        else
          certs
        end
      end
    end

    def configuration
      WebAuthn.configuration
    end
  end
end
