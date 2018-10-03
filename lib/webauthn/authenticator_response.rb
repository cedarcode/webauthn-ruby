# frozen_string_literal: true

module WebAuthn
  class AuthenticatorResponse
    def initialize(client_data_json:)
      @client_data_json = client_data_json
    end

    def valid?(original_challenge, original_origin)
      valid_type? &&
        valid_challenge?(original_challenge) &&
        valid_origin?(original_origin) &&
        valid_rp_id?(original_origin) &&
        authenticator_data.valid? &&
        authenticator_data.user_present?
    end

    def client_data
      @client_data ||= WebAuthn::ClientData.new(client_data_json)
    end

    private

    attr_reader :client_data_json

    def valid_type?
      client_data.type == type
    end

    def valid_challenge?(original_challenge)
      WebAuthn::Utils.authenticator_decode(client_data.challenge) == original_challenge
    end

    def valid_origin?(original_origin)
      client_data.origin == original_origin
    end

    def valid_rp_id?(original_origin)
      domain = URI.parse(original_origin).host

      OpenSSL::Digest::SHA256.digest(domain) == authenticator_data.rp_id_hash
    end

    def type
      raise NotImplementedError, "Please define #type method in subclass"
    end
  end
end
