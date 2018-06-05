# frozen_string_literal: true

require "webauthn/authenticator_attestation_response"
require "webauthn/authenticator_assertion_response"
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
      challenge: challenge,
      pubKeyCredParams: [ES256_ALGORITHM],
      rp: { name: RP_NAME },
      user: { name: USER_NAME, displayName: USER_NAME, id: USER_ID }
    }
  end

  def self.credential_request_options
    {
      challenge: challenge,
      allowCredentials: []
    }
  end

  def self.challenge
    SecureRandom.random_bytes(16)
  end
  private_class_method :challenge
end
