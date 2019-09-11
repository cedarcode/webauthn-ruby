# frozen_string_literal: true

require "spec_helper"

require "base64"
require "securerandom"
require "webauthn/authenticator_attestation_response"
require "webauthn/configuration"
require "webauthn/public_key_credential"
require "webauthn/public_key_credential_with_attestation"

RSpec.describe "PublicKeyCredential" do
  describe "#verify" do
    let(:public_key_credential) do
      WebAuthn::PublicKeyCredentialWithAttestation.new(
        type: type,
        id: id,
        raw_id: raw_id,
        response: attestation_response
      )
    end

    let(:type) { "public-key" }
    let(:id) { Base64.urlsafe_encode64(raw_id) }
    let(:raw_id) { SecureRandom.random_bytes(16) }

    let(:attestation_response) do
      response = client.create(challenge: raw_challenge)["response"]

      WebAuthn::AuthenticatorAttestationResponse.new(
        attestation_object: response["attestationObject"],
        client_data_json: response["clientDataJSON"]
      )
    end

    let(:client) { WebAuthn::FakeClient.new(origin) }
    let(:challenge) { Base64.urlsafe_encode64(raw_challenge) }
    let(:raw_challenge) { fake_challenge }
    let(:origin) { fake_origin }

    before do
      WebAuthn.configuration.origin = origin
    end

    it "works" do
      expect(public_key_credential.verify(challenge)).to be_truthy

      expect(public_key_credential.id).not_to be_empty
      expect(public_key_credential.public_key).not_to be_empty
      expect(public_key_credential.sign_count).to eq(0)
    end

    context "when type is invalid" do
      context "because it is missing" do
        let(:type) { nil }

        it "fails" do
          expect { public_key_credential.verify(challenge) }.to raise_error(RuntimeError)
        end
      end

      context "because it is something else" do
        let(:type) { "password" }

        it "fails" do
          expect { public_key_credential.verify(challenge) }.to raise_error(RuntimeError)
        end
      end
    end

    context "when id is invalid" do
      context "because it is missing" do
        let(:id) { nil }

        it "fails" do
          expect { public_key_credential.verify(challenge) }.to raise_error(RuntimeError)
        end
      end

      context "because it is not the base64url of raw id" do
        let(:id) { Base64.urlsafe_encode64(raw_id + "a") }

        it "fails" do
          expect { public_key_credential.verify(challenge) }.to raise_error(RuntimeError)
        end
      end
    end

    context "when challenge is invalid" do
      it "fails" do
        expect {
          public_key_credential.verify(Base64.urlsafe_encode64("another challenge"))
        }.to raise_error(WebAuthn::ChallengeVerificationError)
      end
    end
  end

  let(:origin) { fake_origin }

  before do
    WebAuthn.configuration.origin = origin
  end

  describe ".from_create" do
    let(:challenge) do
      WebAuthn::PublicKeyCredential.create_options(user: { id: "1", name: "User" }).challenge
    end

    let(:client) { WebAuthn::FakeClient.new(origin, encoding: encoding) }

    before do
      WebAuthn.configuration.encoding = encoding
    end

    context "when encoding is base64url" do
      let(:encoding) { :base64url }

      it "works" do
        credential = client.create(challenge: Base64.urlsafe_decode64(challenge))
        public_key_credential = WebAuthn::PublicKeyCredential.from_create(credential)

        expect(public_key_credential.verify(challenge)).to be_truthy

        expect(public_key_credential.id).not_to be_empty
        expect(public_key_credential.public_key).not_to be_empty
        expect(public_key_credential.public_key.class).to eq(String)
        expect(public_key_credential.public_key.encoding).not_to eq(Encoding::BINARY)
        expect(public_key_credential.sign_count).to eq(0)
      end
    end

    context "when encoding is base64" do
      let(:encoding) { :base64 }

      it "works" do
        credential = client.create(challenge: Base64.strict_decode64(challenge))
        public_key_credential = WebAuthn::PublicKeyCredential.from_create(credential)

        expect(public_key_credential.verify(challenge)).to be_truthy

        expect(public_key_credential.id).not_to be_empty
        expect(public_key_credential.public_key).not_to be_empty
        expect(public_key_credential.public_key.class).to eq(String)
        expect(public_key_credential.public_key.encoding).not_to eq(Encoding::BINARY)
        expect(public_key_credential.sign_count).to eq(0)
      end
    end

    context "when not encoding" do
      let(:encoding) { false }

      it "works" do
        credential = client.create(challenge: challenge)
        public_key_credential = WebAuthn::PublicKeyCredential.from_create(credential)

        expect(public_key_credential.verify(challenge)).to be_truthy

        expect(public_key_credential.id).not_to be_empty
        expect(public_key_credential.public_key).not_to be_empty
        expect(public_key_credential.public_key.class).to eq(String)
        expect(public_key_credential.public_key.encoding).to eq(Encoding::BINARY)
        expect(public_key_credential.sign_count).to eq(0)
      end
    end
  end

  describe ".from_get" do
    let(:challenge) do
      WebAuthn::PublicKeyCredential.get_options({}).challenge
    end

    let(:client) { WebAuthn::FakeClient.new(origin, encoding: encoding) }

    let(:public_key_credential_from_create) do
      WebAuthn::PublicKeyCredential.from_create(created_credential)
    end

    let(:created_credential) { client.create }

    let(:public_key) { public_key_credential_from_create.public_key }
    let(:sign_count) { public_key_credential_from_create.sign_count }

    before do
      WebAuthn.configuration.encoding = encoding

      # Client needs to have a created credential before getting one
      created_credential
    end

    context "when encoding is base64url" do
      let(:encoding) { :base64url }

      it "works" do
        credential = client.get(challenge: Base64.urlsafe_decode64(challenge))
        public_key_credential = WebAuthn::PublicKeyCredential.from_get(credential)

        expect(public_key_credential.verify(challenge, public_key: public_key, sign_count: sign_count)).to be_truthy

        expect(public_key_credential.id).not_to be_empty
        expect(public_key_credential.user_handle).to be_nil
        expect(public_key_credential.sign_count).to eq(1)
      end
    end

    context "when encoding is base64" do
      let(:encoding) { :base64 }

      it "works" do
        credential = client.get(challenge: Base64.strict_decode64(challenge))
        public_key_credential = WebAuthn::PublicKeyCredential.from_get(credential)

        expect(public_key_credential.verify(challenge, public_key: public_key, sign_count: sign_count)).to be_truthy

        expect(public_key_credential.id).not_to be_empty
        expect(public_key_credential.user_handle).to be_nil
        expect(public_key_credential.sign_count).to eq(1)
      end
    end

    context "when not encoding" do
      let(:encoding) { false }

      it "works" do
        credential = client.get(challenge: challenge)
        public_key_credential = WebAuthn::PublicKeyCredential.from_get(credential)

        expect(public_key_credential.verify(challenge, public_key: public_key, sign_count: sign_count)).to be_truthy

        expect(public_key_credential.id).not_to be_empty
        expect(public_key_credential.user_handle).to be_nil
        expect(public_key_credential.sign_count).to eq(1)
      end
    end
  end
end
