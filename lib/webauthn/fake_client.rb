# frozen_string_literal: true

require "openssl"
require "securerandom"
require "webauthn/authenticator_data"
require "webauthn/encoder"
require "webauthn/fake_authenticator"

module WebAuthn
  class FakeClient
    TYPES = { create: "webauthn.create", get: "webauthn.get" }.freeze

    attr_reader :origin, :token_binding

    def initialize(
      origin = fake_origin,
      token_binding: nil,
      authenticator: WebAuthn::FakeAuthenticator.new,
      encoding: WebAuthn.configuration.encoding
    )
      @origin = origin
      @token_binding = token_binding
      @authenticator = authenticator
      @encoding = encoding
    end

    def create(
      challenge: fake_challenge,
      rp_id: nil,
      user_present: true,
      user_verified: false,
      attested_credential_data: true
    )
      rp_id ||= URI.parse(origin).host

      client_data_json = data_json_for(:create, encoder.decode(challenge))
      client_data_hash = hashed(client_data_json)

      attestation_object = authenticator.make_credential(
        rp_id: rp_id,
        client_data_hash: client_data_hash,
        user_present: user_present,
        user_verified: user_verified,
        attested_credential_data: attested_credential_data
      )

      id =
        if attested_credential_data
          WebAuthn::AuthenticatorData
            .deserialize(CBOR.decode(attestation_object)["authData"])
            .attested_credential_data
            .id
        else
          "id-for-pk-without-attested-credential-data"
        end

      {
        "type" => "public-key",
        "id" => internal_encoder.encode(id),
        "rawId" => encoder.encode(id),
        "response" => {
          "attestationObject" => encoder.encode(attestation_object),
          "clientDataJSON" => encoder.encode(client_data_json)
        }
      }
    end

    def get(challenge: fake_challenge, rp_id: nil, user_present: true, user_verified: false, sign_count: nil)
      rp_id ||= URI.parse(origin).host

      client_data_json = data_json_for(:get, encoder.decode(challenge))
      client_data_hash = hashed(client_data_json)

      assertion = authenticator.get_assertion(
        rp_id: rp_id,
        client_data_hash: client_data_hash,
        user_present: user_present,
        user_verified: user_verified,
        sign_count: sign_count,
      )

      {
        "type" => "public-key",
        "id" => internal_encoder.encode(assertion[:credential_id]),
        "rawId" => encoder.encode(assertion[:credential_id]),
        "response" => {
          "clientDataJSON" => encoder.encode(client_data_json),
          "authenticatorData" => encoder.encode(assertion[:authenticator_data]),
          "signature" => encoder.encode(assertion[:signature]),
          "userHandle" => nil
        }
      }
    end

    private

    attr_reader :authenticator, :encoding

    def data_json_for(method, challenge)
      data = {
        type: type_for(method),
        challenge: internal_encoder.encode(challenge),
        origin: origin
      }

      if token_binding
        data[:tokenBinding] = token_binding
      end

      data.to_json
    end

    def encoder
      @encoder ||= WebAuthn::Encoder.new(encoding)
    end

    def internal_encoder
      WebAuthn.standard_encoder
    end

    def hashed(data)
      OpenSSL::Digest::SHA256.digest(data)
    end

    def fake_challenge
      encoder.encode(SecureRandom.random_bytes(32))
    end

    def fake_origin
      "http://localhost#{rand(1000)}.test"
    end

    def type_for(method)
      TYPES[method]
    end
  end
end
