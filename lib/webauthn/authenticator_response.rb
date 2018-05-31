# frozen_string_literal: true

module WebAuthn
  class AuthenticatorResponse
    def initialize(client_data_json:)
      @client_data_json = client_data_json
    end

    private

    attr_reader :client_data_json

    def valid_type?
      client_data.type == type
    end

    def client_data
      @client_data ||= WebAuthn::ClientData.new(client_data_json)
    end

    def valid_challenge?(original_challenge)
      WebAuthn::Utils.authenticator_decode(client_data.challenge) ==
        WebAuthn::Utils.ua_decode(original_challenge)
    end

    def valid_origin?(original_origin)
      client_data.origin == original_origin
    end

    def type
      raise NotImplementedError, "Please define #type method in subclass"
    end
  end
end
