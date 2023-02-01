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
      backup_eligibility: false,
      backup_state: false,
      attested_credential_data: true,
      sign_count: nil,
      extensions: nil
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
        backup_eligibility: backup_eligibility,
        backup_state: backup_state,
        attested_credential_data: attested_credential_data,
        sign_count: sign_count,
        extensions: extensions
      ).serialize
    end

    def get_assertion(
      rp_id:,
      client_data_hash:,
      user_present: true,
      user_verified: false,
      backup_eligibility: false,
      backup_state: false,
      aaguid: AuthenticatorData::AAGUID,
      sign_count: nil,
      extensions: nil,
      allow_credentials: nil
    )
      credential_options = credentials[rp_id]

      if credential_options
        allow_credentials ||= credential_options.keys
        credential_id = (credential_options.keys & allow_credentials).first
        unless credential_id
          raise "No matching credentials (allowed=#{allow_credentials}) " \
                "found for RP #{rp_id} among credentials=#{credential_options}"
        end

        credential = credential_options[credential_id]
        credential_key = credential[:credential_key]
        credential_sign_count = credential[:sign_count]

        authenticator_data = AuthenticatorData.new(
          rp_id_hash: hashed(rp_id),
          user_present: user_present,
          user_verified: user_verified,
          backup_eligibility: backup_eligibility,
          backup_state: backup_state,
          aaguid: aaguid,
          credential: nil,
          sign_count: sign_count || credential_sign_count,
          extensions: extensions
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
      [SecureRandom.random_bytes(16), OpenSSL::PKey::EC.generate("prime256v1"), 0]
    end

    def hashed(target)
      OpenSSL::Digest::SHA256.digest(target)
    end
  end
end
