# frozen_string_literal: true

require "spec_helper"

require "base64"
require "securerandom"
require "webauthn/authenticator_attestation_response"
require "webauthn/configuration"
require "webauthn/public_key_credential"

RSpec.describe "PublicKeyCredential" do
  describe "#verify" do
    let(:public_key_credential) do
      WebAuthn::PublicKeyCredential.new(
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
      response = client.create(challenge: challenge)[:response]

      WebAuthn::AuthenticatorAttestationResponse.new(
        attestation_object: response[:attestation_object],
        client_data_json: response[:client_data_json]
      )
    end

    let(:client) { WebAuthn::FakeClient.new(origin) }
    let(:challenge) { fake_challenge }
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

    context "when response is invalid" do
      it "fails" do
        expect {
          public_key_credential.verify("another challenge")
        }.to raise_error(WebAuthn::ChallengeVerificationError)
      end
    end
  end

  describe ".from_create" do
    it "works" do
      client = WebAuthn::FakeClient.new(encoding: :base64)
      credential = client.create

      # TODO: Make FakeClient return camelCase string keys instead of snakecase symbols
      public_key_credential = WebAuthn::PublicKeyCredential.from_create(
        {
          "id" => credential[:id],
          "type" => credential[:type],
          "rawId" => credential[:raw_id],
          "response" => {
            "attestationObject" => credential[:response][:attestation_object],
            "clientDataJSON" => credential[:response][:client_data_json],
          }
        },
        encoding: :base64
      )

      expect(public_key_credential).to be_a(WebAuthn::PublicKeyCredential)
      expect(public_key_credential.response).to be_a(WebAuthn::AuthenticatorAttestationResponse)

      expect(public_key_credential.id).not_to be_empty
      expect(public_key_credential.public_key).not_to be_empty
      expect(public_key_credential.sign_count).to eq(0)
    end
  end

  describe ".from_get" do
    it "works" do
      client = WebAuthn::FakeClient.new(encoding: :base64)
      client.create
      credential = client.get

      # TODO: Make FakeClient return camelCase string keys instead of snakecase symbols
      public_key_credential = WebAuthn::PublicKeyCredential.from_get(
        {
          "id" => credential[:id],
          "type" => credential[:type],
          "rawId" => credential[:raw_id],
          "response" => {
            "authenticatorData" => credential[:response][:authenticator_data],
            "clientDataJSON" => credential[:response][:client_data_json],
            "signature" => credential[:response][:signature]
          }
        },
        encoding: :base64
      )

      expect(public_key_credential).to be_a(WebAuthn::PublicKeyCredential)
      expect(public_key_credential.response).to be_a(WebAuthn::AuthenticatorAssertionResponse)

      expect(public_key_credential.id).not_to be_empty
      expect(public_key_credential.public_key).not_to be_empty
      expect(public_key_credential.sign_count).to eq(0)
    end
  end
end
