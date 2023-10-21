# frozen_string_literal: true

require "spec_helper"

require "base64"
require "securerandom"
require "webauthn/authenticator_attestation_response"
require "webauthn/configuration"
require "webauthn/public_key_credential_with_attestation"

RSpec.describe "PublicKeyCredentialWithAttestation" do
  describe "#verify" do
    let(:public_key_credential) do
      WebAuthn::PublicKeyCredentialWithAttestation.new(
        type: type,
        id: id,
        raw_id: raw_id,
        authenticator_attachment: authenticator_attachment,
        response: attestation_response
      )
    end

    let(:type) { "public-key" }
    let(:id) { Base64.urlsafe_encode64(raw_id) }
    let(:raw_id) { SecureRandom.random_bytes(16) }
    let(:authenticator_attachment) { 'platform' }

    let(:attestation_response) do
      response = client.create(challenge: raw_challenge)["response"]

      WebAuthn::AuthenticatorAttestationResponse.new(
        attestation_object: response["attestationObject"],
        client_data_json: response["clientDataJSON"]
      )
    end

    let(:client) { WebAuthn::FakeClient.new(origin, encoding: false) }
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

    context "when challenge class is invalid" do
      it "raise error" do
        expect {
          public_key_credential.verify(nil)
        }.to raise_error(WebAuthn::PublicKeyCredentialWithAttestation::InvalidChallengeError)
      end
    end

    context "when challenge value is invalid" do
      it "fails" do
        expect {
          public_key_credential.verify(Base64.urlsafe_encode64("another challenge"))
        }.to raise_error(WebAuthn::ChallengeVerificationError)
      end
    end

    context "when clientExtensionResults" do
      context "are not received" do
        let(:public_key_credential) do
          WebAuthn::PublicKeyCredentialWithAttestation.new(
            type: type,
            id: id,
            raw_id: raw_id,
            client_extension_outputs: nil,
            response: attestation_response
          )
        end

        it "works" do
          expect(public_key_credential.verify(challenge)).to be_truthy

          expect(public_key_credential.client_extension_outputs).to be_nil
        end
      end

      context "are received" do
        let(:public_key_credential) do
          WebAuthn::PublicKeyCredentialWithAttestation.new(
            type: type,
            id: id,
            raw_id: raw_id,
            client_extension_outputs: { "appid" => "true" },
            response: attestation_response
          )
        end

        it "works" do
          expect(public_key_credential.verify(challenge)).to be_truthy

          expect(public_key_credential.client_extension_outputs).to eq({ "appid" => "true" })
        end
      end
    end

    context "when authentication extension input" do
      context "is not received" do
        let(:attestation_response) do
          response = client.create(challenge: raw_challenge, extensions: nil)["response"]

          WebAuthn::AuthenticatorAttestationResponse.new(
            attestation_object: response["attestationObject"],
            client_data_json: response["clientDataJSON"]
          )
        end

        it "works" do
          expect(public_key_credential.verify(challenge)).to be_truthy

          expect(public_key_credential.authenticator_extension_outputs).to be_nil
        end
      end

      context "is received" do
        let(:attestation_response) do
          response = client.create(
            challenge: raw_challenge,
            extensions: { "txAuthSimple" => "Could you please verify yourself?" }
          )["response"]

          WebAuthn::AuthenticatorAttestationResponse.new(
            attestation_object: response["attestationObject"],
            client_data_json: response["clientDataJSON"]
          )
        end

        it "works" do
          expect(public_key_credential.verify(challenge)).to be_truthy

          expect(public_key_credential.authenticator_extension_outputs)
            .to eq({ "txAuthSimple" => "Could you please verify yourself?" })
        end
      end
    end
  end
end
