require "webauthn/version"
require "securerandom"
require "base64"

module WebAuthn
  def self.registration_payload
    {
      publicKey: {
        challenge: SecureRandom.random_bytes(16),
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        rp: { name: "web-server" },
        user: { name: "web-user", displayName: "web-user", id: Base64.encode64("1") }
      }
    }
  end
end
