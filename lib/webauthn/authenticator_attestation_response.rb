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
    def initialize(attestation_object:, **options)
      super(options)

      @attestation_object = attestation_object
    end

    def valid?(original_challenge, original_origin)
      super &&
        attestation_statement.valid?(authenticator_data, client_data.hash)
    end

    def credential
      authenticator_data.credential
    end

    private

    attr_reader :attestation_object

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
      @attestation ||= CBOR.decode(WebAuthn::Utils.ua_decode(attestation_object))
    end

    def type
      WebAuthn::TYPES[:create]
    end
  end
end
