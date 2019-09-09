# frozen_string_literal: true

require "webauthn/configuration"
require "webauthn/credential_creation_options"
require "webauthn/credential_request_options"
require "webauthn/public_key_credential"
require "webauthn/version"

module WebAuthn
  def self.generate_user_id
    WebAuthn::Encoder.new.encode(SecureRandom.random_bytes(64))
  end
end
