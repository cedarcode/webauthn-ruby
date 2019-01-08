# frozen_string_literal: true

require "spec_helper"
require "support/seeds"

require "webauthn/authenticator_attestation_response"
require "openssl"

RSpec.describe WebAuthn::AuthenticatorAttestationResponse do
  context "when everything's in place" do
    let(:original_challenge) { fake_challenge }
    let(:origin) { fake_origin }

    let(:attestation_response) do
      authenticator = WebAuthn::FakeAuthenticator::Create.new(
        challenge: original_challenge,
        context: { origin: origin }
      )

      WebAuthn::AuthenticatorAttestationResponse.new(
        attestation_object: authenticator.attestation_object,
        client_data_json: authenticator.client_data_json
      )
    end

    it "is valid" do
      expect(attestation_response.valid?(original_challenge, origin)).to be_truthy
    end

    it "returns the credential" do
      credential = attestation_response.credential

      expect(credential.id.class).to eq(String)
      expect(credential.id.encoding).to eq(Encoding::ASCII_8BIT)
      expect(credential.public_key.class).to eq(String)
      expect(credential.public_key.encoding).to be(Encoding::ASCII_8BIT)
    end
  end

  context "when fido-u2f attestation" do
    let(:original_challenge) do
      Base64.strict_decode64(seeds[:security_key_direct][:credential_creation_options][:challenge])
    end

    let(:original_origin) { "http://localhost:3000" }

    let(:response) do
      response = seeds[:security_key_direct][:authenticator_attestation_response]

      WebAuthn::AuthenticatorAttestationResponse.new(
        attestation_object: Base64.strict_decode64(response[:attestation_object]),
        client_data_json: Base64.strict_decode64(response[:client_data_json])
      )
    end

    it "is valid" do
      expect(response.valid?(original_challenge, original_origin)).to eq(true)
    end

    it "returns attestation info" do
      # TODO: Remove the need for #valid? to be called first
      response.valid?(original_challenge, original_origin)

      expect(response.attestation_type).to eq("Basic_or_AttCA")
      expect(response.attestation_trust_path).to all(be_kind_of(OpenSSL::X509::Certificate))
    end

    it "returns the credential" do
      expect(response.credential.id.length).to be >= 16
    end
  end

  context "when packed attestation (self attestation)" do
    let(:original_origin) { "https://localhost:13010" }

    let(:original_challenge) do
      Base64.strict_decode64(
        seeds[:security_key_packed_self][:credential_creation_options][:challenge]
      )
    end

    let(:response) do
      response = seeds[:security_key_packed_self][:authenticator_attestation_response]

      WebAuthn::AuthenticatorAttestationResponse.new(
        attestation_object: Base64.strict_decode64(response[:attestation_object]),
        client_data_json: Base64.strict_decode64(response[:client_data_json])
      )
    end

    it "is valid" do
      expect(response.valid?(original_challenge, original_origin)).to eq(true)
    end

    it "returns attestation info" do
      # TODO: Remove the need for #valid? to be called first
      response.valid?(original_challenge, original_origin)

      expect(response.attestation_type).to eq("Self")
      expect(response.attestation_trust_path).to eq(nil)
    end

    it "returns credential" do
      expect(response.credential.id.length).to be >= 16
    end
  end

  context "when android-safetynet attestation" do
    let(:original_origin) { "http://localhost:3000" }

    let(:original_challenge) do
      Base64.strict_decode64(seeds[:android_safetynet_direct][:credential_creation_options][:challenge])
    end

    let(:response) do
      response = seeds[:android_safetynet_direct][:authenticator_attestation_response]

      WebAuthn::AuthenticatorAttestationResponse.new(
        attestation_object: Base64.strict_decode64(response[:attestation_object]),
        client_data_json: Base64.strict_decode64(response[:client_data_json])
      )
    end

    it "is valid" do
      # FIXME
      pending "Test seed certificate expired, see https://github.com/cedarcode/webauthn-ruby/issues/105"

      expect(response.valid?(original_challenge, original_origin)).to eq(true)
    end

    it "returns attestation info" do
      # FIXME
      pending "Test seed certificate expired, see https://github.com/cedarcode/webauthn-ruby/issues/105"

      # TODO: Remove the need for #valid? to be called first
      response.valid?(original_challenge, original_origin)

      expect(response.attestation_type).to eq("Basic")
      expect(response.attestation_trust_path).to be_kind_of(OpenSSL::X509::Certificate)
    end

    it "returns the credential" do
      expect(response.credential.id.length).to be >= 16
    end
  end

  it "returns user-friendly error if no client data received" do
    response = WebAuthn::AuthenticatorAttestationResponse.new(
      attestation_object: "",
      client_data_json: nil
    )

    expect {
      response.valid?("", "")
    }.to raise_exception(WebAuthn::ClientDataMissingError)
  end

  describe "origin validation" do
    let(:original_origin) { "http://localhost" }
    let(:original_challenge) { fake_challenge }
    let(:authenticator) {
      WebAuthn::FakeAuthenticator::Create.new(challenge: original_challenge, context: { origin: origin })
    }

    context "matches the default one" do
      let(:origin) { "http://localhost" }

      it "is valid" do
        response = WebAuthn::AuthenticatorAttestationResponse.new(
          attestation_object: authenticator.attestation_object,
          client_data_json: authenticator.client_data_json
        )

        expect(response.valid?(original_challenge, original_origin)).to be_truthy
      end
    end

    context "doesn't match the default one" do
      let(:origin) { "http://invalid" }

      it "isn't valid" do
        response = WebAuthn::AuthenticatorAttestationResponse.new(
          attestation_object: authenticator.attestation_object,
          client_data_json: authenticator.client_data_json
        )

        expect(response.valid?(original_challenge, original_origin)).to be_falsy
      end
    end
  end

  describe "rp_id validation" do
    let(:original_origin) { fake_origin }
    let(:original_challenge) { fake_challenge }
    let(:authenticator) { WebAuthn::FakeAuthenticator::Create.new(challenge: original_challenge, rp_id: rp_id) }

    context "matches the default one" do
      let(:rp_id) { "localhost" }

      it "is valid" do
        response = WebAuthn::AuthenticatorAttestationResponse.new(
          attestation_object: authenticator.attestation_object,
          client_data_json: authenticator.client_data_json
        )

        expect(response.valid?(original_challenge, original_origin)).to be_truthy
      end
    end

    context "doesn't match the default one" do
      let(:rp_id) { "invalid" }

      it "is invalid" do
        response = WebAuthn::AuthenticatorAttestationResponse.new(
          attestation_object: authenticator.attestation_object,
          client_data_json: authenticator.client_data_json
        )

        expect(response.valid?(original_challenge, original_origin)).to be_falsy
      end
    end

    context "matches the one explicitly given" do
      let(:rp_id) { "custom" }

      it "is valid" do
        response = WebAuthn::AuthenticatorAttestationResponse.new(
          attestation_object: authenticator.attestation_object,
          client_data_json: authenticator.client_data_json
        )

        expect(response.valid?(original_challenge, original_origin, rp_id: "custom")).to be_truthy
      end
    end
  end
end
