# frozen_string_literal: true

require "webauthn/encoder"

module WebAuthn
  class PublicKeyCredential
    attr_reader :type, :id, :raw_id, :client_extension_outputs, :response

    def self.from_client(credential, relying_party: WebAuthn.configuration)
      new(
        type: credential["type"],
        id: credential["id"],
        raw_id: relying_party.encoder.decode(credential["rawId"]),
        client_extension_outputs: credential["clientExtensionResults"],
        response: response_class.from_client(credential["response"], relying_party: relying_party),
        encoder: relying_party.encoder
      )
    end

    def initialize(
      type:,
      id:,
      raw_id:,
      response:,
      client_extension_outputs: {},
      encoder: WebAuthn.configuration.encoder
    )
      @type = type
      @id = id
      @raw_id = raw_id
      @client_extension_outputs = client_extension_outputs
      @response = response
      @encoder = encoder
    end

    def verify(*_args)
      valid_type? || raise("invalid type")
      valid_id? || raise("invalid id")

      true
    end

    def sign_count
      authenticator_data&.sign_count
    end

    def authenticator_extension_outputs
      authenticator_data.extension_data if authenticator_data&.extension_data_included?
    end

    private

    attr_reader :encoder

    def valid_type?
      type == TYPE_PUBLIC_KEY
    end

    def valid_id?
      raw_id && id && raw_id == WebAuthn.standard_encoder.decode(id)
    end

    def authenticator_data
      response&.authenticator_data
    end
  end
end
