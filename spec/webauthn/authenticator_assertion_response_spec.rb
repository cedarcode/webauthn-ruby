# frozen_string_literal: true

require "spec_helper"
require "webauthn/authenticator_assertion_response"

RSpec.describe WebAuthn::AuthenticatorAssertionResponse do
  let(:authenticator) do
    WebAuthn::FakeAuthenticator::Get.new(challenge: original_challenge, context: { origin: original_origin })
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

  context "when everything's in place" do
    it "verifies" do
      expect(
        assertion_response.verify(
          original_challenge,
          original_origin,
          allowed_credentials: allowed_credentials
        )
      ).to be_truthy
    end

    it "is valid" do
      expect(
        assertion_response.valid?(
          original_challenge,
          original_origin,
          allowed_credentials: allowed_credentials
        )
      ).to be_truthy
    end
  end

  context "with more than one allowed credential" do
    let(:allowed_credentials) do
      [
        {
          id: credential_id,
          public_key: key_bytes(credential_key.public_key)
        },
        {
          id: SecureRandom.random_bytes(16),
          public_key: key_bytes(OpenSSL::PKey::EC.new("prime256v1").generate_key.public_key)
        }
      ]
    end

    it "verifies" do
      expect(
        assertion_response.verify(
          original_challenge,
          original_origin,
          allowed_credentials: allowed_credentials
        )
      ).to be_truthy
    end

    it "is valid" do
      expect(
        assertion_response.valid?(
          original_challenge,
          original_origin,
          allowed_credentials: allowed_credentials
        )
      ).to be_truthy
    end
  end

  context "if signature was signed with a different key" do
    let(:credentials) do
      [
        {
          id: credential_id,
          public_key: key_bytes(WebAuthn::FakeAuthenticator::Create.new.credential_key.public_key)
        }
      ]
    end

    it "is invalid" do
      expect(
        assertion_response.valid?(
          original_challenge,
          original_origin,
          allowed_credentials: credentials
        )
      ).to be_falsy
    end

    it "doesn't verify" do
      expect {
        assertion_response.verify(
          original_challenge,
          original_origin,
          allowed_credentials: credentials
        )
      }.to raise_exception(WebAuthn::InvalidSignatureError)
    end
  end

  context "if credential id is not among the allowed ones" do
    let(:credentials) do
      [
        {
          id: SecureRandom.random_bytes(16),
          public_key: key_bytes(credential_key.public_key)
        }
      ]
    end

    it "doesn't verify" do
      expect {
        assertion_response.verify(
          original_challenge,
          original_origin,
          allowed_credentials: credentials
        )
      }.to raise_exception(WebAuthn::InvalidCredentialError)
    end

    it "is invalid" do
      expect(
        assertion_response.valid?(
          original_challenge,
          original_origin,
          allowed_credentials: credentials
        )
      ).to be_falsy
    end
  end

  describe "type validation" do
    let(:authenticator) do
      WebAuthn::FakeAuthenticator::Get.new(challenge: original_challenge, context: { origin: original_origin })
    end

    context "if type is create instead of get" do
      before do
        allow(authenticator).to receive(:type).and_return("webauthn.create")
      end

      it "doesn't verify" do
        expect {
          assertion_response.verify(
            original_challenge,
            original_origin,
            allowed_credentials: allowed_credentials
          )
        }.to raise_exception(WebAuthn::InvalidTypeError)
      end

      it "is invalid" do
        expect(
          assertion_response.valid?(
            original_challenge,
            original_origin,
            allowed_credentials: allowed_credentials
          )
        ).to be_falsy
      end
    end
  end

  describe "user present validation" do
    let(:authenticator) do
      WebAuthn::FakeAuthenticator::Get.new(
        challenge: original_challenge,
        context: { origin: original_origin, user_present: false, user_verified: false }
      )
    end

    context "if user flags are off" do
      it "doesn't verify" do
        expect {
          assertion_response.verify(
            original_challenge,
            original_origin,
            allowed_credentials: allowed_credentials
          )
        }.to raise_exception(WebAuthn::UserNotPresentError)
      end

      it "is invalid" do
        expect(
          assertion_response.valid?(
            original_challenge,
            original_origin,
            allowed_credentials: allowed_credentials
          )
        ).to be_falsy
      end
    end
  end

  describe "challenge validation" do
    context "if challenge doesn't match" do
      it "doesn't verify" do
        expect {
          assertion_response.verify(
            fake_challenge,
            original_origin,
            allowed_credentials: allowed_credentials
          )
        }.to raise_exception(WebAuthn::InvalidChallengeError)
      end

      it "is invalid" do
        expect(
          assertion_response.valid?(
            fake_challenge,
            original_origin,
            allowed_credentials: allowed_credentials
          )
        ).to be_falsy
      end
    end
  end

  describe "origin validation" do
    context "if origin doesn't match" do
      it "doesn't verify" do
        expect {
          assertion_response.verify(
            original_challenge,
            "http://different-origin",
            allowed_credentials: allowed_credentials
          )
        }.to raise_exception(WebAuthn::InvalidOriginError)
      end

      it "is invalid" do
        expect(
          assertion_response.valid?(
            original_challenge,
            "http://different-origin",
            allowed_credentials: allowed_credentials
          )
        ).to be_falsy
      end
    end
  end

  describe "rp_id validation" do
    let(:authenticator) do
      WebAuthn::FakeAuthenticator::Get.new(
        challenge: original_challenge,
        rp_id: "different-rp_id",
        context: { origin: original_origin }
      )
    end

    context "if rp_id_hash doesn't match" do
      it "doesn't verify" do
        expect {
          assertion_response.verify(
            original_challenge,
            original_origin,
            allowed_credentials: allowed_credentials
          )
        }.to raise_exception(WebAuthn::InvalidRPIdError)
      end

      it "is invalid" do
        expect(
          assertion_response.valid?(
            original_challenge,
            original_origin,
            allowed_credentials: allowed_credentials
          )
        ).to be_falsy
      end
    end

    context "when correct rp_id is explicitly given" do
      it "verifies" do
        expect(
          assertion_response.verify(
            original_challenge,
            original_origin,
            allowed_credentials: allowed_credentials,
            rp_id: "different-rp_id",
          )
        ).to be_truthy
      end

      it "is valid" do
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
