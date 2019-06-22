# frozen_string_literal: true

require "base64"
require "webauthn/authenticator_attestation_response"

module WebAuthn
  class PublicKeyCredential
    VALID_TYPE = "public-key"

    attr_reader :type, :id, :raw_id, :response

    def self.from_create(credential)
      new(
        type: credential["type"],
        id: credential["id"],
        raw_id: decode(credential["rawId"]),
        response: WebAuthn::AuthenticatorAttestationResponse.new(
          attestation_object: decode(credential["response"]["attestationObject"]),
          client_data_json: decode(credential["response"]["clientDataJSON"])
        )
      )
    end

    def self.decode(data)
      Base64.urlsafe_decode64(data)
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
