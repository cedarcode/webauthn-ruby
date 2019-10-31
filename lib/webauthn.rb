# frozen_string_literal: true

require "webauthn/configuration"
require "webauthn/credential"
require "webauthn/credential_creation_options"
require "webauthn/credential_request_options"
require "webauthn/version"

module WebAuthn
  TYPE_PUBLIC_KEY = "public-key"

  def self.generate_user_id
    configuration.encoder.encode(SecureRandom.random_bytes(64))
  end
end
