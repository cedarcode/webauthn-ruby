# frozen_string_literal: true

require "spec_helper"
require "webauthn/attestation_statement/fido_u2f/public_key"
require "webauthn/authenticator_assertion_response"

RSpec.describe WebAuthn::AuthenticatorAssertionResponse do
  let(:client) { WebAuthn::FakeClient.new(original_origin) }

  let!(:credential) { create_credential(client: client) }
  let(:credential_id) { credential[0] }
  let(:credential_public_key) { credential[1] }

  let(:allowed_credentials) { [{ id: credential_id, public_key: credential_public_key }] }

  let(:original_origin) { fake_origin }
  let(:original_challenge) { fake_challenge }
  let(:assertion) { client.get(challenge: original_challenge) }
  let(:authenticator_data) { assertion[:response][:authenticator_data] }

  let(:assertion_response) do
    WebAuthn::AuthenticatorAssertionResponse.new(
      credential_id: assertion[:id],
      client_data_json: assertion[:response][:client_data_json],
      authenticator_data: authenticator_data,
      signature: assertion[:response][:signature]
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

  # Backwards compatibility with v1.10.0 or lower
  context "when everything's in place with the old public key format" do
    it "verifies" do
      allowed_credentials[0][:public_key] =
        WebAuthn::AttestationStatement::FidoU2f::PublicKey
        .new(allowed_credentials[0][:public_key])
        .to_uncompressed_point

      expect(
        assertion_response.verify(
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
          public_key: credential_public_key
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
      _different_id, different_public_key = create_credential(client: client)

      [{ id: credential_id, public_key: different_public_key }]
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
      }.to raise_exception(WebAuthn::SignatureVerificationError)
    end
  end

  context "if credential id is not among the allowed ones" do
    let(:credentials) do
      [
        {
          id: SecureRandom.random_bytes(16),
          public_key: credential_public_key
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
      }.to raise_exception(WebAuthn::CredentialVerificationError)
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
    context "if type is create instead of get" do
      before do
        allow(client).to receive(:type_for).and_return("webauthn.create")
      end

      it "doesn't verify" do
        expect {
          assertion_response.verify(
            original_challenge,
            original_origin,
            allowed_credentials: allowed_credentials
          )
        }.to raise_exception(WebAuthn::TypeVerificationError)
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
    let(:assertion) { client.get(challenge: original_challenge, user_present: false, user_verified: false) }

    context "if user flags are off" do
      it "doesn't verify" do
        expect {
          assertion_response.verify(
            original_challenge,
            original_origin,
            allowed_credentials: allowed_credentials
          )
        }.to raise_exception(WebAuthn::UserPresenceVerificationError)
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
        }.to raise_exception(WebAuthn::ChallengeVerificationError)
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
        }.to raise_exception(WebAuthn::OriginVerificationError)
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
    let!(:credential) { create_credential(client: client, rp_id: "different-rp_id") }
    let(:assertion) { client.get(challenge: original_challenge, rp_id: "different-rp_id") }

    context "if rp_id_hash doesn't match" do
      it "doesn't verify" do
        expect {
          assertion_response.verify(
            original_challenge,
            original_origin,
            allowed_credentials: allowed_credentials
          )
        }.to raise_exception(WebAuthn::RpIdVerificationError)
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

  context "when Authenticator Data is invalid" do
    let(:authenticator_data) { assertion[:response][:authenticator_data][0..31] }

    it "doesn't verify" do
      expect {
        assertion_response.verify(
          original_challenge,
          original_origin,
          allowed_credentials: allowed_credentials
        )
      }.to raise_exception(WebAuthn::AuthenticatorDataVerificationError)
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
