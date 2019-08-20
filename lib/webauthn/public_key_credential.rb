# frozen_string_literal: true

require "base64"
require "webauthn/authenticator_assertion_response"
require "webauthn/authenticator_attestation_response"
require "webauthn/encoder"
require "webauthn/public_key_credential/creation_options"
require "webauthn/public_key_credential/request_options"

module WebAuthn
  class PublicKeyCredential
    TYPE_PUBLIC_KEY = "public-key"

    attr_reader :type, :id, :raw_id, :response

    def self.from_create(credential, encoding: :base64url)
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

    def self.from_get(credential, encoding: :base64url)
      encoder = WebAuthn::Encoder.new(encoding)

      user_handle =
        if credential["response"]["userHandle"]
          encoder.decode(credential["response"]["userHandle"])
        end

      new(
        type: credential["type"],
        id: credential["id"],
        raw_id: encoder.decode(credential["rawId"]),
        response: WebAuthn::AuthenticatorAssertionResponse.new(
          authenticator_data: encoder.decode(credential["response"]["authenticatorData"]),
          client_data_json: encoder.decode(credential["response"]["clientDataJSON"]),
          signature: encoder.decode(credential["response"]["signature"]),
          user_handle: user_handle
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

    def public_key
      response&.authenticator_data&.credential&.public_key
    end

    def user_handle
      if response.is_a?(WebAuthn::AuthenticatorAssertionResponse)
        response.user_handle
      end
    end

    def sign_count
      response&.authenticator_data&.sign_count
    end

    private

    def valid_type?
      type == TYPE_PUBLIC_KEY
    end

    def valid_id?
      raw_id && id && raw_id == Base64.urlsafe_decode64(id)
    end
  end
end
