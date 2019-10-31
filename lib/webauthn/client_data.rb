# frozen_string_literal: true

require "json"
require "openssl"
require "webauthn/encoder"
require "webauthn/error"

module WebAuthn
  class ClientDataMissingError < Error; end

  class ClientData
    VALID_TOKEN_BINDING_STATUSES = ["present", "supported", "not-supported"].freeze

    def initialize(client_data_json)
      @client_data_json = client_data_json
    end

    def type
      data["type"]
    end

    def challenge
      WebAuthn.standard_encoder.decode(data["challenge"])
    end

    def origin
      data["origin"]
    end

    def token_binding
      data["tokenBinding"]
    end

    def valid_token_binding_format?
      if token_binding
        token_binding.is_a?(Hash) && VALID_TOKEN_BINDING_STATUSES.include?(token_binding["status"])
      else
        true
      end
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
            raise ClientDataMissingError, "Client Data JSON is missing"
          end
        end
    end
  end
end
