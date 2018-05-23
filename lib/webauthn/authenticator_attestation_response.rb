# frozen_string_literal: true

require "cbor"

module WebAuthn
  class AuthenticatorAttestationResponse
    ATTESTATION_FORMAT_NONE = "none"
    AUTHENTICATOR_DATA_MIN_LENGTH = 37
    USER_PRESENT_BIT_POSITION = 0

    def initialize(attestation_object:, client_data_json:)
      @attestation_object = attestation_object
      @client_data_json = client_data_json
    end

    def valid?(original_challenge)
      valid_type? &&
        valid_challenge?(original_challenge) &&
        valid_authenticator_data? &&
        user_present? &&
        valid_attestation_statement?
    end

    private

    attr_reader :attestation_object, :client_data_json

    def valid_type?
      client_data["type"] == CREATE_TYPE
    end

    def valid_challenge?(original_challenge)
      Base64.urlsafe_decode64(client_data["challenge"]) == Base64.urlsafe_decode64(original_challenge)
    end

    def valid_authenticator_data?
      authenticator_data.length > AUTHENTICATOR_DATA_MIN_LENGTH
    end

    def valid_attestation_statement?
      if attestation_format == ATTESTATION_FORMAT_NONE
        true
      else
        raise "Unsupported attestation format '#{attestation_format}'"
      end
    end

    def user_present?
      authenticator_data_flags[USER_PRESENT_BIT_POSITION] == "1"
    end

    def authenticator_data_flags
      @authenticator_data_flags ||= authenticator_data[32].unpack("b*").first
    end

    def client_data
      @client_data ||=
        begin
          if client_data_json
            JSON.parse(Base64.urlsafe_decode64(client_data_json))
          else
            raise "Missing client_data_json"
          end
        end
    end

    def authenticator_data
      @authenticator_data ||= attestation["authData"]
    end

    def attestation_format
      attestation["fmt"]
    end

    def attestation
      @attestation ||= CBOR.decode(Base64.urlsafe_decode64(attestation_object))
    end
  end
end
