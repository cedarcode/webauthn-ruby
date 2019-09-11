# frozen_string_literal: true

require "webauthn/encoder"
require "webauthn/public_key_credential/creation_options"
require "webauthn/public_key_credential/request_options"

module WebAuthn
  class PublicKeyCredential
    TYPE_PUBLIC_KEY = "public-key"

    attr_reader :type, :id, :raw_id, :response

    # XXX: Keep or remove?
    def self.from_create(credential)
      require "webauthn/public_key_credential_with_attestation"
      PublicKeyCredentialWithAttestation.from_client(credential)
    end

    # XXX: Keep or remove?
    def self.from_get(credential)
      require "webauthn/public_key_credential_with_assertion"
      PublicKeyCredentialWithAssertion.from_client(credential)
    end

    def initialize(type:, id:, raw_id:, response:)
      @type = type
      @id = id
      @raw_id = raw_id
      @response = response
    end

    def verify(*_args)
      valid_type? || raise("invalid type")
      valid_id? || raise("invalid id")

      true
    end

    def sign_count
      response&.authenticator_data&.sign_count
    end

    private

    def valid_type?
      type == TYPE_PUBLIC_KEY
    end

    def valid_id?
      raw_id && id && raw_id == WebAuthn.standard_encoder.decode(id)
    end

    def encoder
      WebAuthn.configuration.encoder
    end
  end
end
