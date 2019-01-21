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

    def verify(original_challenge, original_origin, rp_id: nil)
      super && verify_item(:attestation_statement)
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

    private

    attr_reader :attestation_object

    def type
      WebAuthn::TYPES[:create]
    end

    def valid_attestation_statement?
      @attestation_type, @attestation_trust_path = attestation_statement.valid?(authenticator_data, client_data.hash)
    end
  end
end
