# frozen_string_literal: true

require "cose/ecdsa"
require "webauthn/authenticator_attestation_response"
require "webauthn/authenticator_assertion_response"
require "webauthn/utils"
require "webauthn/version"

require "base64"
require "securerandom"
require "json"

module WebAuthn
  CRED_PARAM_ES256 = { type: "public-key", alg: COSE::ECDSA::ALG_ES256 }.freeze
  RP_NAME = "web-server"
  USER_ID = "1"
  USER_NAME = "web-user"
  TYPES = { create: "webauthn.create", get: "webauthn.get" }.freeze

  def self.credential_creation_options
    {
      challenge: challenge,
      pubKeyCredParams: [CRED_PARAM_ES256],
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
