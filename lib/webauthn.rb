require "webauthn/version"
require "securerandom"
require "base64"

module WebAuthn
  ES256_ALGORITHM = { type: "public-key", alg: -7 }.freeze
  RP_NAME = "web-server".freeze
  USER_ID = "1".freeze
  USER_NAME = "web-user".freeze

  def self.registration_payload
    {
      publicKey: {
        challenge: SecureRandom.random_bytes(16),
        pubKeyCredParams: [ES256_ALGORITHM],
        rp: { name: RP_NAME },
        user: { name: USER_NAME, displayName: USER_NAME, id: Base64.encode64(USER_ID) }
      }
    }
  end
end
