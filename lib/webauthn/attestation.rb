# frozen_string_literal: true

require "webauthn/authenticator_attestation_response"

module WebAuthn
  module Attestation
    def self.from_json(attestation)
      attestation[:type] == "public-key" || raise("Invalid credential type")
      Base64.urlsafe_decode64(attestation[:id]) || raise("Missing id")
      response = attestation[:response] || raise("Missing response")

      WebAuthn::AuthenticatorAttestationResponse.new(
        attestation_object: Base64.urlsafe_decode64(response[:attestationObject]),
        client_data_json: Base64.urlsafe_decode64(response[:clientDataJSON])
      )
    end
  end
end
