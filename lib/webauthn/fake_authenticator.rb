# frozen_string_literal: true

require "cbor"
require "openssl"
require "securerandom"
require "webauthn/fake_authenticator/attestation_object"
require "webauthn/fake_authenticator/authenticator_data"

module WebAuthn
  class FakeAuthenticator
    def initialize
      @credentials = {}
    end

    def make_credential(rp_id:, client_data_hash:, user_present: true, user_verified: false)
      credential_id, credential_key = new_credential

      attestation_object = AttestationObject.new(
        client_data_hash: client_data_hash,
        rp_id_hash: hashed(rp_id),
        credential_id: credential_id,
        credential_key: credential_key,
        user_present: user_present,
        user_verified: user_verified
      ).serialize

      credentials[rp_id] ||= {}
      credentials[rp_id][credential_id] = credential_key

      attestation_object
    end

    def get_assertion(
      rp_id:,
      client_data_hash:,
      user_present: true,
      user_verified: false,
      aaguid: AuthenticatorData::AAGUID
    )
      credential_options = credentials[rp_id]

      if credential_options
        credential_id, credential_key = credential_options.first

        authenticator_data = AuthenticatorData.new(
          rp_id_hash: hashed(rp_id),
          user_present: user_present,
          user_verified: user_verified,
          aaguid: aaguid,
        ).serialize

        signature = credential_key.sign("SHA256", authenticator_data + client_data_hash)

        {
          credential_id: credential_id,
          authenticator_data: authenticator_data,
          signature: signature
        }
      else
        raise "No credentials found for RP #{rp_id}"
      end
    end

    private

    attr_reader :credentials

    def new_credential
      [SecureRandom.random_bytes(16), OpenSSL::PKey::EC.new("prime256v1").generate_key]
    end

    def hashed(target)
      OpenSSL::Digest::SHA256.digest(target)
    end
  end
end
