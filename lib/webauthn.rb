# frozen_string_literal: true

require "webauthn/authenticator_attestation_response"
require "webauthn/utils"
require "webauthn/version"

require "base64"
require "securerandom"
require "json"

module WebAuthn
  ES256_ALGORITHM = { type: "public-key", alg: -7 }.freeze
  RP_NAME = "web-server"
  USER_ID = "1"
  USER_NAME = "web-user"
  TYPES = { create: "webauthn.create", get: "webauthn.get" }.freeze

  def self.credential_creation_options
    {
      challenge: ua_encoded_challenge,
      pubKeyCredParams: [ES256_ALGORITHM],
      rp: { name: RP_NAME },
      user: { name: USER_NAME, displayName: USER_NAME, id: Utils.ua_encode(USER_ID) }
    }
  end

  def self.credential_request_options
    {
      challenge: ua_encoded_challenge,
      allowCredentials: []
    }
  end

  def self.ua_encoded_challenge
    Utils.ua_encode(SecureRandom.random_bytes(16))
  end
  private_class_method :ua_encoded_challenge
end
