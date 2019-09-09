# frozen_string_literal: true

require "webauthn/configuration"
require "webauthn/credential_creation_options"
require "webauthn/credential_request_options"
require "webauthn/public_key_credential"
require "webauthn/version"

module WebAuthn
  def self.generate_user_id(encoding: :base64url)
    encoder = WebAuthn::Encoder.new(encoding)
    encoder.encode(SecureRandom.random_bytes(64))
  end
end
