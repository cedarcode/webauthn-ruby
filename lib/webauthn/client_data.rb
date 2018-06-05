# frozen_string_literal: true

require "openssl"

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

    def hash
      OpenSSL::Digest::SHA256.digest(client_data_json)
    end

    private

    attr_reader :client_data_json

    def data
      @data ||=
        begin
          if client_data_json
            JSON.parse(client_data_json)
          else
            raise "Missing client_data_json"
          end
        end
    end
  end
end
