# frozen_string_literal: true

require "cbor"
require "webauthn/statement_validator"

module WebAuthn
  class Validator
    ATTESTATION_FORMAT_NONE = "none"
    ATTESTATION_FORMAT_FIDO_U2F = "fido-u2f"
    AUTHENTICATOR_DATA_MIN_LENGTH = 37
    USER_PRESENT_BIT_POSITION = 0

    def initialize(attestation_object:, client_data_bin:, original_challenge:)
      @attestation_object = attestation_object
      @client_data_bin = client_data_bin
      @original_challenge = original_challenge
    end

    def valid?
      valid_type? &&
        valid_challenge? &&
        valid_authenticator_data? &&
        user_present? &&
        valid_attestation_statement?
    end

    private

    attr_reader :attestation_object, :client_data_bin, :original_challenge

    def valid_type?
      client_data["type"] == CREATE_TYPE
    end

    def valid_challenge?
      Base64.urlsafe_decode64(client_data["challenge"]) == Base64.urlsafe_decode64(original_challenge)
    end

    def valid_authenticator_data?
      authenticator_data.length > AUTHENTICATOR_DATA_MIN_LENGTH
    end

    def valid_attestation_statement?
      case attestation_format
      when ATTESTATION_FORMAT_NONE
        true
      when ATTESTATION_FORMAT_FIDO_U2F
        WebAuthn::StatementValidator.new(attestation_statement).valid?
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
          if client_data_bin
            JSON.parse(Base64.urlsafe_decode64(client_data_bin))
          else
            raise "Missing client_data_bin"
          end
        end
    end

    def authenticator_data
      @authenticator_data ||= attestation["authData"]
    end

    def attestation_format
      attestation["fmt"]
    end

    def attestation_statement
      attestation["attStmt"]
    end

    def attestation
      @attestation ||= CBOR.decode(Base64.urlsafe_decode64(attestation_object))
    end
  end
end
