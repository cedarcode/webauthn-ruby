# frozen_string_literal: true

require "cbor"

require "webauthn/authenticator_data"
require "webauthn/client_data"

module WebAuthn
  class AuthenticatorAttestationResponse
    ATTESTATION_FORMAT_NONE = "none"

    def initialize(attestation_object:, client_data_json:)
      @attestation_object = attestation_object
      @client_data_json = client_data_json
    end

    def valid?(original_challenge)
      valid_type? &&
        valid_challenge?(original_challenge) &&
        authenticator_data.valid? &&
        user_present? &&
        valid_attestation_statement?
    end

    private

    attr_reader :attestation_object, :client_data_json

    def valid_type?
      client_data.type == CREATE_TYPE
    end

    def valid_challenge?(original_challenge)
      Base64.urlsafe_decode64(client_data.challenge) == Base64.urlsafe_decode64(original_challenge)
    end

    def valid_attestation_statement?
      if attestation_format == ATTESTATION_FORMAT_NONE
        true
      else
        raise "Unsupported attestation format '#{attestation_format}'"
      end
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
      @attestation ||= CBOR.decode(Base64.urlsafe_decode64(attestation_object))
    end
  end
end
