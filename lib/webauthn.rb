# frozen_string_literal: true

require "webauthn/authenticator_attestation_response"
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
      challenge: ua_encode(SecureRandom.random_bytes(16)),
      pubKeyCredParams: [ES256_ALGORITHM],
      rp: { name: RP_NAME },
      user: { name: USER_NAME, displayName: USER_NAME, id: ua_encode(USER_ID) }
    }
  end

  def self.ua_encode(bin)
    Base64.strict_encode64(bin)
  end

  def self.ua_decode(str)
    Base64.strict_decode64(str)
  end

  def self.authenticator_decode(str)
    Base64.urlsafe_decode64(str)
  end
end
