# frozen_string_literal: true

require "webauthn/encoder"

module WebAuthn
  class PublicKeyCredential
    class InvalidChallengeError < Error; end

    attr_reader :type, :id, :raw_id, :client_extension_outputs, :authenticator_attachment, :response

    def self.from_client(credential, relying_party: WebAuthn.configuration.relying_party)
      new(
        type: credential["type"],
        id: credential["id"],
        raw_id: relying_party.encoder.decode(credential["rawId"]),
        client_extension_outputs: credential["clientExtensionResults"],
        authenticator_attachment: credential["authenticatorAttachment"],
        response: response_class.from_client(credential["response"], relying_party: relying_party),
        relying_party: relying_party
      )
    end

    def initialize(
      type:,
      id:,
      raw_id:,
      response:,
      authenticator_attachment: nil,
      client_extension_outputs: {},
      relying_party: WebAuthn.configuration.relying_party
    )
      @type = type
      @id = id
      @raw_id = raw_id
      @client_extension_outputs = client_extension_outputs
      @authenticator_attachment = authenticator_attachment
      @response = response
      @relying_party = relying_party
    end

    def verify(challenge, *_args)
      unless valid_class?(challenge)
        msg = "challenge must be a String. input challenge class: #{challenge.class}"

        raise(InvalidChallengeError, msg)
      end

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

    def backup_eligible?
      authenticator_data&.credential_backup_eligible?
    end

    def backed_up?
      authenticator_data&.credential_backed_up?
    end

    private

    attr_reader :relying_party

    def valid_type?
      type == TYPE_PUBLIC_KEY
    end

    def valid_id?
      raw_id && id && raw_id == WebAuthn.standard_encoder.decode(id)
    end

    def valid_class?(challenge)
      challenge.is_a?(String)
    end

    def authenticator_data
      response&.authenticator_data
    end

    def encoder
      relying_party.encoder
    end
  end
end
