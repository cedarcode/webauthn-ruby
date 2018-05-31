# frozen_string_literal: true

require "webauthn/authenticator_assertion_response"

RSpec.describe WebAuthn::AuthenticatorAssertionResponse do
  let(:challenge) { fake_challenge }
  let(:encoded_challenge) { WebAuthn::Utils.ua_encode(challenge) }
  let(:original_origin) { fake_origin }

  it "is valid if everything's in place" do
    credential_key = fake_credential_key
    client_data_json = fake_client_data_json(challenge: challenge, origin: original_origin, type: "webauthn.get")
    authenticator_data = fake_authenticator_data(credential_public_key: credential_key.public_key)

    assertion_response = WebAuthn::AuthenticatorAssertionResponse.new(
      client_data_json: WebAuthn::Utils.ua_encode(client_data_json),
      authenticator_data: authenticator_data,
      signature: fake_signature(
        key: credential_key,
        authenticator_data: authenticator_data,
        client_data_json: client_data_json
      )
    )

    is_valid = assertion_response.valid?(
      encoded_challenge,
      original_origin,
      credential_public_key: credential_key.public_key.to_octet_string(:uncompressed)
    )

    expect(is_valid).to be_truthy
  end

  it "is invalid if signature was signed with a different key" do
    credential_key = fake_credential_key
    client_data_json = fake_client_data_json(challenge: challenge, origin: original_origin, type: "webauthn.get")
    authenticator_data = fake_authenticator_data(credential_public_key: credential_key.public_key)

    assertion_response = WebAuthn::AuthenticatorAssertionResponse.new(
      client_data_json: WebAuthn::Utils.ua_encode(client_data_json),
      authenticator_data: authenticator_data,
      signature: fake_signature(
        key: credential_key,
        authenticator_data: authenticator_data,
        client_data_json: client_data_json
      )
    )

    different_key = fake_credential_key

    is_valid = assertion_response.valid?(
      encoded_challenge,
      original_origin,
      credential_public_key: different_key.public_key.to_octet_string(:uncompressed)
    )

    expect(is_valid).to be_falsy
  end

  describe "type validation" do
    it "is invalid if type is not get" do
      credential_key = fake_credential_key
      client_data_json = fake_client_data_json(challenge: challenge, origin: original_origin, type: "webauthn.create")
      authenticator_data = fake_authenticator_data(credential_public_key: credential_key.public_key)

      assertion_response = WebAuthn::AuthenticatorAssertionResponse.new(
        client_data_json: WebAuthn::Utils.ua_encode(client_data_json),
        authenticator_data: authenticator_data,
        signature: fake_signature(
          key: credential_key,
          authenticator_data: authenticator_data,
          client_data_json: client_data_json
        )
      )

      is_valid = assertion_response.valid?(
        encoded_challenge,
        original_origin,
        credential_public_key: credential_key.public_key.to_octet_string(:uncompressed)
      )

      expect(is_valid).to be_falsy
    end
  end

  describe "user present validation" do
    it "is invalid if user-present flag is off" do
      credential_key = fake_credential_key
      client_data_json = fake_client_data_json(challenge: challenge, origin: original_origin, type: "webauthn.get")
      authenticator_data = fake_authenticator_data(credential_public_key: credential_key.public_key, user_present: false)

      assertion_response = WebAuthn::AuthenticatorAssertionResponse.new(
        client_data_json: WebAuthn::Utils.ua_encode(client_data_json),
        authenticator_data: authenticator_data,
        signature: fake_signature(
          key: credential_key,
          authenticator_data: authenticator_data,
          client_data_json: client_data_json
        )
      )

      is_valid = assertion_response.valid?(
        encoded_challenge,
        original_origin,
        credential_public_key: credential_key.public_key.to_octet_string(:uncompressed)
      )

      expect(is_valid).to be_falsy
    end
  end

  describe "challenge validation" do
    it "is invalid if challenge doesn't match" do
      credential_key = fake_credential_key
      client_data_json = fake_client_data_json(challenge: challenge, origin: original_origin, type: "webauthn.get")
      authenticator_data = fake_authenticator_data(credential_public_key: credential_key.public_key)

      original_challenge = fake_challenge
      encoded_original_challenge = WebAuthn::Utils.ua_encode(original_challenge)

      assertion_response = WebAuthn::AuthenticatorAssertionResponse.new(
        client_data_json: WebAuthn::Utils.ua_encode(client_data_json),
        authenticator_data: authenticator_data,
        signature: fake_signature(
          key: credential_key,
          authenticator_data: authenticator_data,
          client_data_json: client_data_json
        )
      )

      is_valid = assertion_response.valid?(
        encoded_original_challenge,
        original_origin,
        credential_public_key: credential_key.public_key.to_octet_string(:uncompressed)
      )

      expect(is_valid).to be_falsy
    end
  end

  describe "origin validation" do
    it "is invalid if origin doesn't match" do
      credential_key = fake_credential_key
      client_data_json = fake_client_data_json(challenge: challenge, origin: original_origin, type: "webauthn.get")
      authenticator_data = fake_authenticator_data(credential_public_key: credential_key.public_key)

      assertion_response = WebAuthn::AuthenticatorAssertionResponse.new(
        client_data_json: WebAuthn::Utils.ua_encode(client_data_json),
        authenticator_data: authenticator_data,
        signature: fake_signature(
          key: credential_key,
          authenticator_data: authenticator_data,
          client_data_json: client_data_json
        )
      )

      expect(
        assertion_response.valid?(
          encoded_challenge,
          "http://different-origin",
          credential_public_key: credential_key.public_key.to_octet_string(:uncompressed)
        )
      ).to be_falsy
    end
  end
end
