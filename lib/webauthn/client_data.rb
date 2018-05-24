# frozen_string_literal: true

module WebAuthn
  class ClientData
    def initialize(client_data_json)
      @client_data_json = client_data_json
    end

    def type
      data["type"]
    end

    def challenge
      data["challenge"]
    end

    def origin
      data["origin"]
    end

    private

    attr_reader :client_data_json

    def data
      @data ||=
        begin
          if client_data_json
            JSON.parse(Base64.urlsafe_decode64(client_data_json))
          else
            raise "Missing client_data_json"
          end
        end
    end
  end
end
