# frozen_string_literal: true

require "spec_helper"

require "webauthn/configuration"
require "webauthn/credential"

RSpec.describe "Credential" do
  let(:origin) { fake_origin }

  before do
    WebAuthn.configuration.origin = origin
  end

  describe ".from_create" do
    let(:challenge) do
      WebAuthn::Credential.options_for_create(user: { id: "1", name: "User" }).challenge
    end

    let(:client) { WebAuthn::FakeClient.new(origin) }

    before do
      WebAuthn.configuration.encoding = encoding
    end

    context "when encoding is base64url" do
      let(:encoding) { :base64url }

      it "works" do
        credential = WebAuthn::Credential.from_create(client.create(challenge: challenge))

        expect(credential.verify(challenge)).to be_truthy

        expect(credential.id).not_to be_empty
        expect(credential.public_key).not_to be_empty
        expect(credential.public_key.class).to eq(String)
        expect(credential.public_key.encoding).not_to eq(Encoding::BINARY)
        expect(credential.sign_count).to eq(0)
      end
    end

    context "when encoding is base64" do
      let(:encoding) { :base64 }

      it "works" do
        credential = WebAuthn::Credential.from_create(client.create(challenge: challenge))

        expect(credential.verify(challenge)).to be_truthy

        expect(credential.id).not_to be_empty
        expect(credential.public_key).not_to be_empty
        expect(credential.public_key.class).to eq(String)
        expect(credential.public_key.encoding).not_to eq(Encoding::BINARY)
        expect(credential.sign_count).to eq(0)
      end
    end

    context "when not encoding" do
      let(:encoding) { false }

      it "works" do
        credential = WebAuthn::Credential.from_create(client.create(challenge: challenge))

        expect(credential.verify(challenge)).to be_truthy

        expect(credential.id).not_to be_empty
        expect(credential.public_key).not_to be_empty
        expect(credential.public_key.class).to eq(String)
        expect(credential.public_key.encoding).to eq(Encoding::BINARY)
        expect(credential.sign_count).to eq(0)
      end
    end
  end

  describe ".from_get" do
    let(:challenge) do
      WebAuthn::Credential.options_for_get.challenge
    end

    let(:client) { WebAuthn::FakeClient.new(origin) }

    let(:credential_from_create) do
      WebAuthn::Credential.from_create(created_credential)
    end

    let(:created_credential) { client.create }

    let(:public_key) { credential_from_create.public_key }
    let(:sign_count) { credential_from_create.sign_count }

    before do
      WebAuthn.configuration.encoding = encoding

      # Client needs to have a created credential before getting one
      created_credential
    end

    context "when encoding is base64url" do
      let(:encoding) { :base64url }

      it "works" do
        credential = WebAuthn::Credential.from_get(client.get(challenge: challenge))

        expect(credential.verify(challenge, public_key: public_key, sign_count: sign_count)).to be_truthy

        expect(credential.id).not_to be_empty
        expect(credential.user_handle).to be_nil
        expect(credential.sign_count).to eq(1)
      end
    end

    context "when encoding is base64" do
      let(:encoding) { :base64 }

      it "works" do
        credential = WebAuthn::Credential.from_get(client.get(challenge: challenge))

        expect(credential.verify(challenge, public_key: public_key, sign_count: sign_count)).to be_truthy

        expect(credential.id).not_to be_empty
        expect(credential.user_handle).to be_nil
        expect(credential.sign_count).to eq(1)
      end
    end

    context "when not encoding" do
      let(:encoding) { false }

      it "works" do
        credential = WebAuthn::Credential.from_get(client.get(challenge: challenge))

        expect(credential.verify(challenge, public_key: public_key, sign_count: sign_count)).to be_truthy

        expect(credential.id).not_to be_empty
        expect(credential.user_handle).to be_nil
        expect(credential.sign_count).to eq(1)
      end
    end
  end
end
