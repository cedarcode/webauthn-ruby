require "webauthn/version"
require "securerandom"
require "base64"
require "json"

module WebAuthn
  ES256_ALGORITHM = { type: "public-key", alg: -7 }.freeze
  RP_NAME = "web-server".freeze
  USER_ID = "1".freeze
  USER_NAME = "web-user".freeze
  CREATE_TYPE = "webauthn.create"

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

  def self.valid?(original_challenge:, client_data_bin:)
    client_data_text = Base64.urlsafe_decode64(client_data_bin)
    client_data = JSON.parse(client_data_text)

    client_data["type"] == CREATE_TYPE && Base64.urlsafe_decode64(client_data["challenge"]) == original_challenge
  end
end
