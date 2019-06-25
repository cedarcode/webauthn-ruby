# frozen_string_literal: true

require "base64"
require "openssl"
require "webauthn/authenticator_data"
require "webauthn/fake_authenticator"

module WebAuthn
  class FakeClient
    TYPES = { create: "webauthn.create", get: "webauthn.get" }.freeze

    attr_reader :origin, :token_binding

    def initialize(origin = fake_origin, token_binding: nil, authenticator: WebAuthn::FakeAuthenticator.new)
      @origin = origin
      @token_binding = token_binding
      @authenticator = authenticator
    end

    def create(challenge: fake_challenge, rp_id: nil, user_present: true, user_verified: false)
      rp_id ||= URI.parse(origin).host

      client_data_json = data_json_for(:create, challenge)
      client_data_hash = hashed(client_data_json)

      attestation_object = authenticator.make_credential(
        rp_id: rp_id,
        client_data_hash: client_data_hash,
        user_present: user_present,
        user_verified: user_verified
      )

      id = WebAuthn::AuthenticatorData.new(CBOR.decode(attestation_object)["authData"]).credential.id

      {
        id: id,
        response: {
          attestation_object: attestation_object,
          client_data_json: client_data_json
        }
      }
    end

    def get(challenge: fake_challenge, rp_id: nil, user_present: true, user_verified: false, sign_count: nil)
      rp_id ||= URI.parse(origin).host

      client_data_json = data_json_for(:get, challenge)
      client_data_hash = hashed(client_data_json)

      assertion = authenticator.get_assertion(
        rp_id: rp_id,
        client_data_hash: client_data_hash,
        user_present: user_present,
        user_verified: user_verified,
        sign_count: sign_count,
      )

      {
        id: assertion[:credential_id],
        response: {
          client_data_json: client_data_json,
          authenticator_data: assertion[:authenticator_data],
          signature: assertion[:signature]
        }
      }
    end

    private

    attr_reader :authenticator

    def data_json_for(method, challenge)
      data = {
        type: type_for(method),
        challenge: encode(challenge),
        origin: origin
      }

      if token_binding
        data[:tokenBinding] = token_binding
      end

      data.to_json
    end

    def encode(data)
      Base64.urlsafe_encode64(data, padding: false)
    end

    def hashed(data)
      OpenSSL::Digest::SHA256.digest(data)
    end

    def fake_challenge
      SecureRandom.random_bytes(32)
    end

    def fake_origin
      "http://localhost#{rand(1000)}"
    end

    def type_for(method)
      TYPES[method]
    end
  end
end
