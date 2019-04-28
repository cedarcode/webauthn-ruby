# frozen_string_literal: true

require "cose/algorithm"
require "webauthn/authenticator_attestation_response"
require "webauthn/authenticator_assertion_response"
require "webauthn/configuration"
require "webauthn/security_utils"
require "webauthn/version"

require "base64"
require "securerandom"
require "json"

module WebAuthn
  DEFAULT_ALGORITHMS = ["ES256", "RS256"].freeze

  DEFAULT_PUB_KEY_CRED_PARAMS = DEFAULT_ALGORITHMS.map do |alg_name|
    { type: "public-key", alg: COSE::Algorithm.by_name(alg_name).id }
  end.freeze

  TYPES = { create: "webauthn.create", get: "webauthn.get" }.freeze

  def self.configuration
    @configuration ||= Configuration.new
  end

  def self.configure
    yield(configuration)
  end

  # TODO: make keyword arguments mandatory in next major version
  def self.credential_creation_options(rp_name: nil, user_name: "web-user", display_name: "web-user", user_id: "1")
    {
      challenge: challenge,
      pubKeyCredParams: DEFAULT_PUB_KEY_CRED_PARAMS,
      rp: { name: rp_name || configuration.rp_name || "web-server" },
      user: { name: user_name, displayName: display_name, id: user_id }
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
