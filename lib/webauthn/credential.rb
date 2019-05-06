# frozen_string_literal: true

require "webauthn/authenticator_assertion_response"
require "webauthn/authenticator_attestation_response"
require "webauthn/client_utils"

module WebAuthn
  class Credential
    def self.from_json(json)
      id = WebAuthn::ClientUtils.decode(json["id"])
      response_json = json["response"]

      response =
        if response_json["attestationObject"]
          AuthenticatorAttestationResponse.from_json(response_json)
        elsif response_json["signature"]
          AuthenticatorAssertionResponse.from_json(response_json, id)
        else
          raise "invalid response"
        end

      new(id: id, response: response)
    end

    attr_reader :id, :response

    def initialize(id:, response:)
      @id = id
      @response = response
    end

    def verify(expected_challenge, public_key = nil)
      case response
      when AuthenticatorAttestationResponse
        response.verify(expected_challenge)
      when AuthenticatorAssertionResponse
        response.verify(expected_challenge, allowed_credentials: [{ id: id, public_key: public_key }])
      end
    end

    def public_key
      # Verify first?
      response.credential.public_key
    end
  end
end
