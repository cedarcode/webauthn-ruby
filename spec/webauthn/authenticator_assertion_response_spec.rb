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
  let(:allowed_credentials) {
    [{
      id: credential_id,
      public_key: key_bytes(credential_key.public_key)
    }]
  }
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
        allowed_credentials: allowed_credentials
      )
    ).to be_truthy
  end

  it "is valid with more than one allowed credential" do
    other_credential_key = OpenSSL::PKey::EC.new("prime256v1").generate_key
    allowed_credentials << {
      id: SecureRandom.random_bytes(16),
      public_key: key_bytes(other_credential_key.public_key)
    }

    expect(
      assertion_response.valid?(
        original_challenge,
        original_origin,
        allowed_credentials: allowed_credentials
      )
    ).to be_truthy
  end

  it "is invalid if signature was signed with a different key" do
    credentials = [
      {
        id: credential_id,
        public_key: key_bytes(FakeAuthenticator::Create.new.credential_key.public_key)
      }
    ]

    expect(
      assertion_response.valid?(
        original_challenge,
        original_origin,
        allowed_credentials: credentials
      )
    ).to be_falsy
  end

  it "is invalid if credential id is not among the allowed ones" do
    credentials = [
      {
        id: SecureRandom.random_bytes(16),
        public_key: key_bytes(credential_key.public_key)
      }
    ]

    expect(
      assertion_response.valid?(
        original_challenge,
        original_origin,
        allowed_credentials: credentials
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
          allowed_credentials: allowed_credentials
        )
      ).to be_falsy
    end
  end

  describe "user present validation" do
    let(:authenticator) do
      FakeAuthenticator::Get.new(
        challenge: original_challenge,
        context: { origin: original_origin, user_present: false, user_verified: false }
      )
    end

    it "is invalid if user flags are off" do
      expect(
        assertion_response.valid?(
          original_challenge,
          original_origin,
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
          allowed_credentials: allowed_credentials
        )
      ).to be_falsy
    end

    context "when rp_id is explicitly given" do
      it "is valid if correct rp_id is given" do
        expect(
          assertion_response.valid?(
            original_challenge,
            original_origin,
            allowed_credentials: allowed_credentials,
            rp_id: "different-rp_id",
          )
        ).to be_truthy
      end
    end
  end
end
