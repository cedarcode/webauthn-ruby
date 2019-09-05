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

    def make_credential(
      rp_id:,
      client_data_hash:,
      user_present: true,
      user_verified: false,
      attested_credential_data: true,
      sign_count: nil
    )
      credential_id, credential_key, credential_sign_count = new_credential
      sign_count ||= credential_sign_count

      credentials[rp_id] ||= {}
      credentials[rp_id][credential_id] = {
        credential_key: credential_key,
        sign_count: sign_count + 1
      }

      AttestationObject.new(
        client_data_hash: client_data_hash,
        rp_id_hash: hashed(rp_id),
        credential_id: credential_id,
        credential_key: credential_key,
        user_present: user_present,
        user_verified: user_verified,
        attested_credential_data: attested_credential_data,
        sign_count: sign_count
      ).serialize
    end

    def get_assertion(
      rp_id:,
      client_data_hash:,
      user_present: true,
      user_verified: false,
      aaguid: AuthenticatorData::AAGUID,
      sign_count: nil
    )
      credential_options = credentials[rp_id]

      if credential_options
        credential_id, credential = credential_options.first
        credential_key = credential[:credential_key]
        credential_sign_count = credential[:sign_count]

        authenticator_data = AuthenticatorData.new(
          rp_id_hash: hashed(rp_id),
          user_present: user_present,
          user_verified: user_verified,
          aaguid: aaguid,
          credential: nil,
          sign_count: sign_count || credential_sign_count,
        ).serialize

        signature = credential_key.sign("SHA256", authenticator_data + client_data_hash)
        credential[:sign_count] += 1

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
      [SecureRandom.random_bytes(16), OpenSSL::PKey::EC.new("prime256v1").generate_key, 0]
    end

    def hashed(target)
      OpenSSL::Digest::SHA256.digest(target)
    end
  end
end
