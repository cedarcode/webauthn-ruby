# frozen_string_literal: true

require "cose/algorithm"
require "webauthn/authenticator_attestation_response"
require "webauthn/authenticator_assertion_response"
require "webauthn/security_utils"
require "webauthn/version"

require "base64"
require "securerandom"
require "json"

module WebAuthn
  CRED_PARAM_ES256 = { type: "public-key", alg: COSE::Algorithm.by_name("ES256").id }.freeze
  TYPES = { create: "webauthn.create", get: "webauthn.get" }.freeze

  # TODO: make keyword arguments mandatory in next major version
  def self.credential_creation_options(rp_name: "web-server", user_name: "web-user", display_name: "web-user", id: "1")
    {
      challenge: challenge,
      pubKeyCredParams: [CRED_PARAM_ES256],
      rp: { name: rp_name },
      user: { name: user_name, displayName: display_name, id: id }
    }
  end

  def self.credential_request_options
    {
      challenge: challenge,
      allowCredentials: []
    }
  end

  def self.challenge
    SecureRandom.random_bytes(32)
  end
  private_class_method :challenge
end
