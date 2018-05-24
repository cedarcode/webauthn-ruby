# frozen_string_literal: true

require "cbor"

require "webauthn/authenticator_data"
require "webauthn/attestation_statement"
require "webauthn/client_data"

module WebAuthn
  class AuthenticatorAttestationResponse
    def initialize(attestation_object:, client_data_json:)
      @attestation_object = attestation_object
      @client_data_json = client_data_json
    end

    def valid?(original_challenge, original_origin)
      valid_type? &&
        valid_challenge?(original_challenge) &&
        valid_origin?(original_origin) &&
        authenticator_data.valid? &&
        user_present? &&
        attestation_statement.valid?(authenticator_data, client_data.hash)
    end

    private

    attr_reader :attestation_object, :client_data_json

    def valid_type?
      client_data.type == CREATE_TYPE
    end

    def valid_challenge?(original_challenge)
      Base64.urlsafe_decode64(client_data.challenge) == Base64.urlsafe_decode64(original_challenge)
    end

    def valid_origin?(original_origin)
      client_data.origin == original_origin
    end

    def attestation_statement
      @attestation_statement ||=
        WebAuthn::AttestationStatement.from(attestation["fmt"], attestation["attStmt"])
    end

    def user_present?
      authenticator_data.user_present?
    end

    def client_data
      @client_data ||= WebAuthn::ClientData.new(client_data_json)
    end

    def authenticator_data
      @authenticator_data ||= WebAuthn::AuthenticatorData.new(attestation["authData"])
    end

    def attestation_format
      attestation["fmt"]
    end

    def attestation
      @attestation ||= CBOR.decode(Base64.urlsafe_decode64(attestation_object))
    end
  end
end
