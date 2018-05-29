# frozen_string_literal: true

require "cbor"
require "uri"
require "openssl"

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
        valid_rp_id?(original_origin) &&
        authenticator_data.valid? &&
        user_present? &&
        attestation_statement.valid?(authenticator_data, client_data.hash)
    end

    def credential_id
      authenticator_data.credential_id
    end

    private

    attr_reader :attestation_object, :client_data_json

    def valid_type?
      client_data.type == CREATE_TYPE
    end

    def valid_challenge?(original_challenge)
      WebAuthn::Utils.authenticator_decode(client_data.challenge) == WebAuthn::Utils.ua_decode(original_challenge)
    end

    def valid_origin?(original_origin)
      client_data.origin == original_origin
    end

    def attestation_statement
      @attestation_statement ||=
        WebAuthn::AttestationStatement.from(attestation["fmt"], attestation["attStmt"])
    end

    def valid_rp_id?(original_origin)
      domain = URI.parse(original_origin).host

      OpenSSL::Digest::SHA256.digest(domain) == authenticator_data.rp_id_hash
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
      @attestation ||= CBOR.decode(WebAuthn::Utils.ua_decode(attestation_object))
    end
  end
end
