# frozen_string_literal: true

require "cbor"
require "uri"
require "openssl"

require "webauthn/authenticator_data"
require "webauthn/authenticator_response"
require "webauthn/attestation_statement"
require "webauthn/client_data"

module WebAuthn
  class AuthenticatorAttestationResponse < AuthenticatorResponse
    attr_reader :attestation_type, :attestation_trust_path

    def initialize(attestation_object:, **options)
      super(options)

      @attestation_object = attestation_object
    end

    def verify(original_challenge, original_origin, rp_id: nil)
      valid_response = super
      return false unless valid_response

      valid_attestation = attestation_statement.valid?(authenticator_data, client_data.hash)
      return false unless valid_attestation

      @attestation_type, @attestation_trust_path = valid_attestation
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

    private

    attr_reader :attestation_object

    def type
      WebAuthn::TYPES[:create]
    end
  end
end
