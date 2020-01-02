# frozen_string_literal: true

require "cbor"
require "forwardable"
require "openssl"
require "webauthn/attestation_statement"
require "webauthn/authenticator_data"

module WebAuthn
  class AttestationObject
    extend Forwardable

    def self.deserialize(attestation_object)
      from_map(CBOR.decode(attestation_object), relying_party)
    end

    def self.from_map(map, relying_party)
      new(
        authenticator_data: WebAuthn::AuthenticatorData.deserialize(map["authData"]),
        attestation_statement: WebAuthn::AttestationStatement.from(map["fmt"], map["attStmt"], relying_party),
      )
    end

    attr_reader :authenticator_data, :attestation_statement, :relying_party

    def initialize(authenticator_data:, attestation_statement:)
      @authenticator_data = authenticator_data
      @attestation_statement = attestation_statement
    end

    def valid_attested_credential?
      authenticator_data.attested_credential_data_included? &&
        authenticator_data.attested_credential_data.valid?
    end

    def valid_attestation_statement?(client_data_hash)
      attestation_statement.valid?(authenticator_data, client_data_hash)
    end

    def_delegators :authenticator_data, :credential, :aaguid
    def_delegators :attestation_statement, :attestation_certificate_key_id
  end
end
