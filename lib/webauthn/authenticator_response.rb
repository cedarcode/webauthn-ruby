# frozen_string_literal: true

module WebAuthn
  class AuthenticatorResponse
    def initialize(client_data_json:)
      @client_data_json = client_data_json
    end

    private

    attr_reader :client_data_json

    def client_data
      @client_data ||= WebAuthn::ClientData.new(client_data_json)
    end
  end
end
