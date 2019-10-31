# frozen_string_literal: true

require "webauthn/encoder"

module WebAuthn
  class PublicKeyCredential
    attr_reader :type, :id, :raw_id, :response

    def self.from_client(credential)
      new(
        type: credential["type"],
        id: credential["id"],
        raw_id: WebAuthn.configuration.encoder.decode(credential["rawId"]),
        response: response_class.from_client(credential["response"])
      )
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
