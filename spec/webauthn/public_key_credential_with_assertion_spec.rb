# frozen_string_literal: true

require "spec_helper"

require "base64"
require "securerandom"
require "webauthn/authenticator_assertion_response"
require "webauthn/configuration"
require "webauthn/public_key_credential_with_assertion"

RSpec.describe "PublicKeyCredentialWithAssertion" do
  describe "#verify" do
    let(:client) { WebAuthn::FakeClient.new(origin, encoding: false) }
    let(:challenge) { Base64.urlsafe_encode64(raw_challenge) }
    let(:raw_challenge) { fake_challenge }
    let(:origin) { fake_origin }

    let!(:credential) { create_credential(client: client) }
    let(:credential_raw_id) { credential[0] }
    let(:credential_id) { Base64.urlsafe_encode64(credential_raw_id) }
    let(:credential_type) { "public-key" }
    let(:credential_authenticator_attachment) { 'platform' }
    let(:credential_public_key) { Base64.urlsafe_encode64(credential[1]) }
    let(:credential_sign_count) { credential[2] }

    let(:assertion_response) do
      response = client.get(challenge: raw_challenge, sign_count: 1)["response"]

      WebAuthn::AuthenticatorAssertionResponse.new(
        authenticator_data: response["authenticatorData"],
        client_data_json: response["clientDataJSON"],
        signature: response["signature"]
      )
    end

    let(:public_key_credential) do
      WebAuthn::PublicKeyCredentialWithAssertion.new(
        type: credential_type,
        id: credential_id,
        raw_id: credential_raw_id,
        authenticator_attachment: credential_authenticator_attachment,
        response: assertion_response
      )
    end

    before do
      WebAuthn.configuration.origin = origin
    end

    it "works" do
      expect(
        public_key_credential.verify(challenge, public_key: credential_public_key, sign_count: credential_sign_count)
      ).to be_truthy

      expect(public_key_credential.id).not_to be_empty
      expect(public_key_credential.user_handle).to be_nil
      expect(public_key_credential.sign_count).to eq(credential_sign_count + 1)
    end

    context "when type is invalid" do
      context "because it is missing" do
        let(:credential_type) { nil }

        it "fails" do
          expect do
            public_key_credential.verify(
              challenge,
              public_key: credential_public_key,
              sign_count: credential_sign_count
            )
          end.to raise_error(RuntimeError)
        end
      end

      context "because it is something else" do
        let(:credential_type) { "password" }

        it "fails" do
          expect do
            public_key_credential.verify(
              challenge,
              public_key: credential_public_key,
              sign_count: credential_sign_count
            )
          end.to raise_error(RuntimeError)
        end
      end
    end

    context "when id is invalid" do
      context "because it is missing" do
        let(:credential_id) { nil }

        it "fails" do
          expect do
            public_key_credential.verify(
              challenge,
              public_key: credential_public_key,
              sign_count: credential_sign_count
            )
          end.to raise_error(RuntimeError)
        end
      end

      context "because it is not the base64url of raw id" do
        let(:credential_id) { Base64.urlsafe_encode64(credential_raw_id + "a") }

        it "fails" do
          expect do
            public_key_credential.verify(
              challenge,
              public_key: credential_public_key,
              sign_count: credential_sign_count
            )
          end.to raise_error(RuntimeError)
        end
      end
    end

    context "when challenge is invalid" do
      let(:challenge) { Base64.urlsafe_encode64("another challenge") }

      it "fails" do
        expect do
          public_key_credential.verify(
            challenge,
            public_key: credential_public_key,
            sign_count: credential_sign_count
          )
        end.to raise_error(WebAuthn::ChallengeVerificationError)
      end
    end

    context "when clientExtensionResults" do
      context "is not received" do
        let(:public_key_credential) do
          WebAuthn::PublicKeyCredentialWithAssertion.new(
            type: credential_type,
            id: credential_id,
            raw_id: credential_raw_id,
            client_extension_outputs: nil,
            response: assertion_response
          )
        end

        it "works" do
          expect(
            public_key_credential.verify(
              challenge,
              public_key: credential_public_key,
              sign_count: credential_sign_count
            )
          ).to be_truthy

          expect(public_key_credential.client_extension_outputs).to be_nil
        end
      end

      context "is received" do
        let(:public_key_credential) do
          WebAuthn::PublicKeyCredentialWithAssertion.new(
            type: credential_type,
            id: credential_id,
            raw_id: credential_raw_id,
            client_extension_outputs: { "txAuthSimple" => "Could you please verify yourself?" },
            response: assertion_response
          )
        end

        it "works" do
          expect(
            public_key_credential.verify(
              challenge,
              public_key: credential_public_key,
              sign_count: credential_sign_count
            )
          ).to be_truthy

          expect(public_key_credential.client_extension_outputs)
            .to eq({ "txAuthSimple" => "Could you please verify yourself?" })
        end
      end
    end

    context "when authentication extension input" do
      context "is not received" do
        let(:assertion_response) do
          response = client.get(challenge: raw_challenge, extensions: nil)["response"]

          WebAuthn::AuthenticatorAssertionResponse.new(
            authenticator_data: response["authenticatorData"],
            client_data_json: response["clientDataJSON"],
            signature: response["signature"]
          )
        end

        it "works" do
          expect(
            public_key_credential.verify(
              challenge,
              public_key: credential_public_key,
              sign_count: credential_sign_count
            )
          ).to be_truthy

          expect(public_key_credential.authenticator_extension_outputs).to be_nil
        end
      end

      context "is received" do
        let(:assertion_response) do
          response = client.get(
            challenge: raw_challenge,
            extensions: { "txAuthSimple" => "Could you please verify yourself?" }
          )["response"]

          WebAuthn::AuthenticatorAssertionResponse.new(
            authenticator_data: response["authenticatorData"],
            client_data_json: response["clientDataJSON"],
            signature: response["signature"]
          )
        end

        it "works" do
          expect(
            public_key_credential.verify(
              challenge,
              public_key: credential_public_key,
              sign_count: credential_sign_count
            )
          ).to be_truthy

          expect(public_key_credential.authenticator_extension_outputs)
            .to eq({ "txAuthSimple" => "Could you please verify yourself?" })
        end
      end
    end
  end
end
