# frozen_string_literal: true

require "webauthn/validator"
require "webauthn/version"

require "securerandom"
require "base64"
require "json"

module WebAuthn
  ES256_ALGORITHM = { type: "public-key", alg: -7 }.freeze
  RP_NAME = "web-server"
  USER_ID = "1"
  USER_NAME = "web-user"
  CREATE_TYPE = "webauthn.create"

  def self.credential_creation_options
    {
      challenge: Base64.urlsafe_encode64(SecureRandom.random_bytes(16)),
      pubKeyCredParams: [ES256_ALGORITHM],
      rp: { name: RP_NAME },
      user: { name: USER_NAME, displayName: USER_NAME, id: Base64.urlsafe_encode64(USER_ID) }
    }
  end

  def self.valid?(attestation_object:, client_data_bin:, original_challenge:)
    validator = WebAuthn::Validator.new(
      original_challenge: original_challenge,
      attestation_object: attestation_object,
      client_data_bin: client_data_bin
    )

    validator.valid?
  end
end
