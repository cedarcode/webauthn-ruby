# frozen_string_literal: true

require "webauthn/authenticator_assertion_response"

RSpec.describe WebAuthn::AuthenticatorAssertionResponse do
  let(:authenticator) do
    FakeAuthenticator::Get.new(challenge: original_challenge, context: { origin: original_origin })
  end

  let(:original_challenge) { fake_challenge }
  let(:original_origin) { fake_origin }

  let(:credential_key) { authenticator.credential_key }
  let(:credential_id) { authenticator.credential_id }
  let(:allowed_credentials) { [credential_id] }
  let(:authenticator_data) { authenticator.authenticator_data }

  let(:assertion_response) do
    WebAuthn::AuthenticatorAssertionResponse.new(
      credential_id: credential_id,
      client_data_json: authenticator.client_data_json,
      authenticator_data: authenticator_data,
      signature: authenticator.signature
    )
  end

  it "is valid if everything's in place" do
    expect(
      assertion_response.valid?(
        original_challenge,
        original_origin,
        credential_public_key: key_bytes(credential_key.public_key),
        allowed_credentials: allowed_credentials
      )
    ).to be_truthy
  end

  it "is invalid if signature was signed with a different key" do
    different_key = FakeAuthenticator::Create.new.credential_key

    expect(
      assertion_response.valid?(
        original_challenge,
        original_origin,
        credential_public_key: key_bytes(different_key.public_key),
        allowed_credentials: allowed_credentials
      )
    ).to be_falsy
  end

  describe "type validation" do
    let(:authenticator) do
      FakeAuthenticator::Get.new(challenge: original_challenge, context: { origin: original_origin })
    end

    it "is invalid if type is create instead of get" do
      allow(authenticator).to receive(:type).and_return("webauthn.create")

      expect(
        assertion_response.valid?(
          original_challenge,
          original_origin,
          credential_public_key: key_bytes(credential_key.public_key),
          allowed_credentials: allowed_credentials
        )
      ).to be_falsy
    end
  end

  describe "user present validation" do
    let(:authenticator) do
      FakeAuthenticator::Get.new(
        challenge: original_challenge,
        context: { origin: original_origin, user_present: false }
      )
    end

    it "is invalid if user-present flag is off" do
      expect(
        assertion_response.valid?(
          original_challenge,
          original_origin,
          credential_public_key: key_bytes(credential_key.public_key),
          allowed_credentials: allowed_credentials
        )
      ).to be_falsy
    end
  end

  describe "challenge validation" do
    it "is invalid if challenge doesn't match" do
      expect(
        assertion_response.valid?(
          fake_challenge,
          original_origin,
          credential_public_key: key_bytes(credential_key.public_key),
          allowed_credentials: allowed_credentials
        )
      ).to be_falsy
    end
  end

  describe "origin validation" do
    it "is invalid if origin doesn't match" do
      expect(
        assertion_response.valid?(
          original_challenge,
          "http://different-origin",
          credential_public_key: key_bytes(credential_key.public_key),
          allowed_credentials: allowed_credentials
        )
      ).to be_falsy
    end
  end

  describe "rp_id validation" do
    let(:authenticator) do
      FakeAuthenticator::Get.new(
        challenge: original_challenge,
        rp_id: "different-rp_id",
        context: { origin: original_origin }
      )
    end

    it "is invalid if rp_id_hash doesn't match" do
      expect(
        assertion_response.valid?(
          original_challenge,
          original_origin,
          credential_public_key: key_bytes(credential_key.public_key),
          allowed_credentials: allowed_credentials
        )
      ).to be_falsy
    end
  end

  describe "allowed credentials validation" do
    let(:allowed_credentials) { [SecureRandom.random_bytes(16)] }

    it "is invalid if credential id is not among the allowed ones" do
      expect(
        assertion_response.valid?(
          original_challenge,
          original_origin,
          credential_public_key: key_bytes(credential_key.public_key),
          allowed_credentials: allowed_credentials
        )
      ).to be_falsy
    end
  end
end
