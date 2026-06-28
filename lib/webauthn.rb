# frozen_string_literal: true

require "webauthn/json_serializer"
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

  singleton_class.send(:alias_method, :generate_user_handle, :generate_user_id)
end
