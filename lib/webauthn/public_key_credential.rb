# frozen_string_literal: true

require "base64"

module WebAuthn
  class PublicKeyCredential
    VALID_TYPE = "public-key"

    attr_reader :type, :id, :raw_id, :response

    def initialize(type:, id:, raw_id:, response:)
      @type = type
      @id = id
      @raw_id = raw_id
      @response = response
    end

    def verify(*args)
      valid_type? || raise("invalid type")
      valid_id? || raise("invalid id")
      response.verify(*args)

      true
    end

    private

    def valid_type?
      type == VALID_TYPE
    end

    def valid_id?
      raw_id && id && raw_id == Base64.urlsafe_decode64(id)
    end
  end
end
