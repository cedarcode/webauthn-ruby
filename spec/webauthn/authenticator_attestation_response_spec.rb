# frozen_string_literal: true

require "webauthn/authenticator_attestation_response"
require "openssl"

RSpec.describe WebAuthn::AuthenticatorAttestationResponse do
  it "is valid if everything's in place" do
    challenge = fake_challenge
    original_challenge = WebAuthn::Utils.ua_encode(challenge)
    origin = fake_origin

    attestation_response = WebAuthn::AuthenticatorAttestationResponse.new(
      attestation_object: encoded_fake_attestation_object,
      client_data_json: encoded_fake_client_data_json(challenge: challenge, origin: origin)
    )

    expect(attestation_response.valid?(original_challenge, origin)).to be_truthy

    credential = attestation_response.credential
    expect(credential.id.class).to eq(String)
    expect(credential.id.encoding).to eq(Encoding::ASCII_8BIT)
    expect(credential.public_key.class).to eq(String)
    expect(credential.public_key.encoding).to be(Encoding::ASCII_8BIT)
  end

  # TODO Consider using fake_* spec helpers for examples below

  it "can validate none attestation" do
    original_challenge = fake_challenge
    encoded_challenge = WebAuthn::Utils.ua_encode(original_challenge)

    response = WebAuthn::AuthenticatorAttestationResponse.new(
      attestation_object: encoded_fake_attestation_object,
      client_data_json: encoded_fake_client_data_json(challenge: original_challenge)
    )

    expect(response.valid?(encoded_challenge, "http://localhost")).to eq(true)
    expect(response.credential.id.length).to be >= 16
  end

  it "can validate fido-u2f attestation" do
    original_origin = "http://localhost:3000"
    original_challenge = seeds[:security_key_direct][:credential_creation_options][:challenge]
    response = seeds[:security_key_direct][:authenticator_attestation_response]

    response = WebAuthn::AuthenticatorAttestationResponse.new(
      attestation_object: response[:attestation_object],
      client_data_json: response[:client_data_json]
    )

    expect(response.valid?(original_challenge, original_origin)).to eq(true)
    expect(response.credential.id.length).to be >= 16
  end

  it "returns user-friendly error if no client data received" do
    response = WebAuthn::AuthenticatorAttestationResponse.new(
      attestation_object: "",
      client_data_json: nil
    )

    expect {
      response.valid?("", "")
    }.to raise_exception(RuntimeError, "Missing client_data_json")
  end

  describe "origin validation" do
    let(:original_origin) { "http://localhost" }
    let(:challenge) { fake_challenge }
    let(:encoded_challenge) { WebAuthn::Utils.ua_encode(challenge) }
    let(:client_data_json) {
      encoded_fake_client_data_json(challenge: challenge,
                                    origin: origin)
    }

    let(:attestation_object) {
      hash_to_encoded_cbor(fmt: "none",
                           attStmt: {},
                           authData: fake_authenticator_data)
    }

    context "matches the default one" do
      let(:origin) { "http://localhost" }

      it "is valid" do
        response = WebAuthn::AuthenticatorAttestationResponse.new(
          attestation_object: attestation_object,
          client_data_json: client_data_json
        )

        expect(response.valid?(encoded_challenge, original_origin)).to be_truthy
      end
    end

    context "doesn't match the default one" do
      let(:origin) { "http://invalid" }

      it "isn't valid" do
        response = WebAuthn::AuthenticatorAttestationResponse.new(
          attestation_object: attestation_object,
          client_data_json: client_data_json
        )

        expect(response.valid?(encoded_challenge, original_origin)).to be_falsy
      end
    end
  end

  describe "rp_id validation" do
    let(:original_origin) { fake_origin }
    let(:challenge) { fake_challenge }
    let(:encoded_challenge) { WebAuthn::Utils.ua_encode(challenge) }
    let(:client_data_json) { encoded_fake_client_data_json(challenge: challenge) }

    let(:attestation_object) {
      hash_to_encoded_cbor(fmt: "none",
                           attStmt: {},
                           authData: fake_authenticator_data(rp_id: rp_id))
    }

    context "matches the default one" do
      let(:rp_id) { "localhost" }

      it "is valid" do
        response = WebAuthn::AuthenticatorAttestationResponse.new(
          attestation_object: attestation_object,
          client_data_json: client_data_json
        )

        expect(response.valid?(encoded_challenge, original_origin)).to be_truthy
      end
    end

    context "doesn't match the default one" do
      let(:rp_id) { "invalid" }

      it "is invalid" do
        response = WebAuthn::AuthenticatorAttestationResponse.new(
          attestation_object: attestation_object,
          client_data_json: client_data_json
        )

        expect(response.valid?(encoded_challenge, original_origin)).to be_falsy
      end
    end
  end
end
