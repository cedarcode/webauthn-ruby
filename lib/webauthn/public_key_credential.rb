# frozen_string_literal: true

require "base64"
require "webauthn/authenticator_assertion_response"
require "webauthn/authenticator_attestation_response"
require "webauthn/encoder"

module WebAuthn
  class PublicKeyCredential
    VALID_TYPE = "public-key"

    attr_reader :type, :id, :raw_id, :response

    def self.from_create(credential, encoding: :base64)
      encoder = WebAuthn::Encoder.new(encoding)

      new(
        type: credential["type"],
        id: credential["id"],
        raw_id: encoder.decode(credential["rawId"]),
        response: WebAuthn::AuthenticatorAttestationResponse.new(
          attestation_object: encoder.decode(credential["response"]["attestationObject"]),
          client_data_json: encoder.decode(credential["response"]["clientDataJSON"])
        )
      )
    end

    def self.from_get(credential, encoding: :base64)
      encoder = WebAuthn::Encoder.new(encoding)

      new(
        type: credential["type"],
        id: credential["id"],
        raw_id: encoder.decode(credential["rawId"]),
        response: WebAuthn::AuthenticatorAssertionResponse.new(
          # FIXME: credential_id doesn't belong inside AuthenticatorAssertionResponse
          credential_id: Base64.urlsafe_decode64(credential["id"]),
          authenticator_data: encoder.decode(credential["response"]["authenticatorData"]),
          client_data_json: encoder.decode(credential["response"]["clientDataJSON"]),
          signature: encoder.decode(credential["response"]["signature"])
        )
      )
    end

    def initialize(type:, id:, raw_id:, response:)
      @type = type
      @id = id
      @raw_id = raw_id
      @response = response
    end

    def verify(*args)
      valid_type? || raise("invalid type")
      valid_id? || raise("invalid id")
      response.verify(*args)

      true
    end

    private

    def valid_type?
      type == VALID_TYPE
    end

    def valid_id?
      raw_id && id && raw_id == Base64.urlsafe_decode64(id)
    end
  end
end
