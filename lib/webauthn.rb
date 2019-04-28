# frozen_string_literal: true

require "webauthn/authenticator_attestation_response"
require "webauthn/authenticator_assertion_response"
require "webauthn/configuration"
require "webauthn/credential_creation_options"
require "webauthn/credential_request_options"
require "webauthn/security_utils"
require "webauthn/version"

require "base64"
require "json"

module WebAuthn
  TYPES = { create: "webauthn.create", get: "webauthn.get" }.freeze

  def self.configuration
    @configuration ||= Configuration.new
  end

  def self.configure
    yield(configuration)
  end

  # TODO: make keyword arguments mandatory in next major version
  def self.credential_creation_options(rp_name: nil, user_name: "web-user", display_name: "web-user", user_id: "1")
    CredentialCreationOptions.new(
      rp_name: rp_name, user_id: user_id, user_name: user_name, user_display_name: display_name
    ).to_h
  end

  def self.credential_request_options
    CredentialRequestOptions.new.to_h
  end
end
