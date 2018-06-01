# frozen_string_literal: true

require "webauthn/authenticator_assertion_response"

RSpec.describe WebAuthn::AuthenticatorAssertionResponse do
  let(:authenticator) { FakeAuthenticator.new(challenge: challenge, origin: original_origin, mode: :get) }

  let(:challenge) { fake_challenge }
  let(:encoded_challenge) { WebAuthn::Utils.ua_encode(challenge) }
  let(:original_origin) { fake_origin }

  let(:client_data_json) { authenticator.client_data_json }
  let(:encoded_client_data_json) { WebAuthn::Utils.ua_encode(client_data_json) }
  let(:credential_key) { authenticator.credential_key }
  let(:authenticator_data) { authenticator.authenticator_data }

  let(:assertion_response) do
    WebAuthn::AuthenticatorAssertionResponse.new(
      client_data_json: encoded_client_data_json,
      authenticator_data: authenticator_data,
      signature: authenticator.signature
    )
  end

  it "is valid if everything's in place" do
    expect(
      assertion_response.valid?(
        encoded_challenge,
        original_origin,
        credential_public_key: key_bytes(credential_key.public_key)
      )
    ).to be_truthy
  end

  it "is invalid if signature was signed with a different key" do
    different_key = FakeAuthenticator.new.credential_key

    expect(
      assertion_response.valid?(
        encoded_challenge,
        original_origin,
        credential_public_key: key_bytes(different_key.public_key)
      )
    ).to be_falsy
  end

  describe "type validation" do
    let(:authenticator) { FakeAuthenticator.new(challenge: challenge, origin: original_origin, mode: :create) }

    it "is invalid if type is not get" do
      expect(
        assertion_response.valid?(
          encoded_challenge,
          original_origin,
          credential_public_key: key_bytes(credential_key.public_key)
        )
      ).to be_falsy
    end
  end

  describe "user present validation" do
    let(:authenticator) do
      FakeAuthenticator.new(
        challenge: challenge,
        origin: original_origin,
        mode: :get,
        user_present: false
      )
    end

    it "is invalid if user-present flag is off" do
      expect(
        assertion_response.valid?(
          encoded_challenge,
          original_origin,
          credential_public_key: key_bytes(credential_key.public_key)
        )
      ).to be_falsy
    end
  end

  describe "challenge validation" do
    it "is invalid if challenge doesn't match" do
      expect(
        assertion_response.valid?(
          WebAuthn::Utils.ua_encode(fake_challenge),
          original_origin,
          credential_public_key: key_bytes(credential_key.public_key)
        )
      ).to be_falsy
    end
  end

  describe "origin validation" do
    it "is invalid if origin doesn't match" do
      expect(
        assertion_response.valid?(
          encoded_challenge,
          "http://different-origin",
          credential_public_key: key_bytes(credential_key.public_key)
        )
      ).to be_falsy
    end
  end

  describe "rp_id validation" do
    let(:authenticator) do
      FakeAuthenticator.new(
        challenge: challenge,
        origin: original_origin,
        mode: :get,
        rp_id: "different-rp_id"
      )
    end

    it "is invalid if rp_id_hash doesn't match" do
      expect(
        assertion_response.valid?(
          encoded_challenge,
          original_origin,
          credential_public_key: key_bytes(credential_key.public_key)
        )
      ).to be_falsy
    end
  end
end
