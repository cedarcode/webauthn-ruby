# frozen_string_literal: true

require "spec_helper"

RSpec.describe "PublicKeyCredential" do
  describe "#verify" do
    let(:client) { WebAuthn::FakeClient.new(origin, encoding: false) }
    let(:raw_challenge) { fake_challenge }
    let(:challenge) { Base64.urlsafe_encode64(raw_challenge) }
    let(:origin) { fake_origin }

    let!(:credential) { create_credential(client: client) }
    let(:credential_type) { "public-key" }
    let(:credential_id) { Base64.urlsafe_encode64(credential_raw_id) }
    let(:credential_raw_id) { credential[0] }

    let(:assertion_response) do
      response = client.get(challenge: raw_challenge, sign_count: 1)["response"]

      WebAuthn::AuthenticatorAssertionResponse.new(
        authenticator_data: response["authenticatorData"],
        client_data_json: response["clientDataJSON"],
        signature: response["signature"]
      )
    end

    let(:public_key_credential) do
      WebAuthn::PublicKeyCredential.new(
        type: credential_type,
        id: credential_id,
        raw_id: credential_raw_id,
        response: assertion_response
      )
    end

    before do
      WebAuthn.configuration.origin = origin
    end

    it "return `true`" do
      expect(public_key_credential.verify(challenge)).to be_truthy
    end

    context "when `challenge`` is invalid" do
      let(:invalid_challenge) { nil }

      it "raise `WebAuthn::PublicKeyCredential::InvalidChallengeError`" do
        expect {
          public_key_credential.verify(invalid_challenge)
        }.to raise_error(WebAuthn::PublicKeyCredential::InvalidChallengeError)
      end
    end

    context "when `type` is invalid" do
      let(:invalid_type_public_key_credential) do
        WebAuthn::PublicKeyCredential.new(
          type: 'invalid',
          id: credential_id,
          raw_id: credential_raw_id,
          response: assertion_response
        )
      end

      it "raise `RuntimeError` with message" do
        expect { invalid_type_public_key_credential.verify(challenge) }.to raise_error('invalid type')
      end
    end

    context "when `id` is invalid" do
      let(:invalid_id_public_key_credential) do
        WebAuthn::PublicKeyCredential.new(
          type: credential_type,
          id: Base64.urlsafe_encode64('invalid'),
          raw_id: credential_raw_id,
          response: assertion_response
        )
      end

      it "raise `RuntimeError` with message" do
        expect { invalid_id_public_key_credential.verify(challenge) }.to raise_error('invalid id')
      end
    end
  end
end
