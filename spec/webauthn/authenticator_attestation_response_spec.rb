# frozen_string_literal: true

require "webauthn/authenticator_attestation_response"
require "openssl"

RSpec.describe WebAuthn::AuthenticatorAttestationResponse do
  it "is valid if everything's in place" do
    challenge = fake_challenge
    original_challenge = WebAuthn::Utils.ua_encode(challenge)
    origin = fake_origin

    attestation_response = WebAuthn::AuthenticatorAttestationResponse.new(
      attestation_object: WebAuthn::Utils.ua_encode(fake_attestation_object),
      client_data_json: WebAuthn::Utils.ua_encode(fake_client_data_json(challenge: challenge, origin: origin))
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
    original_challenge = seeds[:security_key][:credential_creation_options][:challenge]
    response = seeds[:security_key][:authenticator_attestation_response]

    response = WebAuthn::AuthenticatorAttestationResponse.new(
      attestation_object: response[:attestation_object],
      client_data_json: response[:client_data_json]
    )

    expect(response.valid?(original_challenge, "http://localhost:3000")).to eq(true)
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
    let(:challenge) { SecureRandom.random_bytes(16) }
    let(:original_challenge) { WebAuthn::Utils.ua_encode(challenge) }
    let(:client_data_json) {
      hash_to_encoded_json(challenge: authenticator_encode(challenge),
                           clientExtensions: {},
                           hashAlgorithm: "SHA-256",
                           origin: origin,
                           type: "webauthn.create")
    }
    let(:auth_data) {
      # TODO Move this to a spec helper which receives options so
      # that it can be configured for different test cases
      [73, 150, 13, 229, 136, 14, 140, 104, 116, 52, 23, 15, 100,
       118, 96, 91, 143, 228, 174, 185, 162, 134, 50, 199, 153,
       92, 243, 186, 131, 29, 151, 99, 1, 0, 0, 0, 0].pack('c*')
    }
    let(:attestation_object) {
      hash_to_encoded_cbor(fmt: "none",
                           attStmt: {},
                           authData: auth_data)
    }

    context "matches the default one" do
      let(:origin) { "http://localhost" }

      it "is valid" do
        response = WebAuthn::AuthenticatorAttestationResponse.new(
          attestation_object: attestation_object,
          client_data_json: client_data_json
        )

        expect(response.valid?(original_challenge, original_origin)).to be_truthy
      end
    end

    context "doesn't match the default one" do
      let(:origin) { "http://invalid" }

      it "isn't valid" do
        response = WebAuthn::AuthenticatorAttestationResponse.new(
          attestation_object: attestation_object,
          client_data_json: client_data_json
        )

        expect(response.valid?(original_challenge, original_origin)).to be_falsy
      end
    end
  end

  describe "rp_id validation" do
    let(:original_origin) { "http://localhost:3000" }
    let(:challenge) { SecureRandom.random_bytes(16) }
    let(:original_challenge) { WebAuthn::Utils.ua_encode(challenge) }
    let(:client_data_json) {
      hash_to_encoded_json(challenge: authenticator_encode(challenge),
                           clientExtensions: {},
                           hashAlgorithm: "SHA-256",
                           origin: original_origin,
                           type: "webauthn.create")
    }

    let(:rp_id_hash) { OpenSSL::Digest::SHA256.digest(rp_id) }
    let(:auth_data) {
      (rp_id_hash.bytes + [1, 0, 0, 0, 0]).pack('c*')
    }
    let(:attestation_object) {
      hash_to_encoded_cbor(fmt: "none",
                           attStmt: {},
                           authData: auth_data)
    }

    context "matches the default one" do
      let(:rp_id) { "localhost" }

      it "is valid" do
        response = WebAuthn::AuthenticatorAttestationResponse.new(
          attestation_object: attestation_object,
          client_data_json: client_data_json
        )

        expect(response.valid?(original_challenge, original_origin)).to be_truthy
      end
    end

    context "doesn't match the default one" do
      let(:rp_id) { "invalid" }

      it "is invalid" do
        response = WebAuthn::AuthenticatorAttestationResponse.new(
          attestation_object: attestation_object,
          client_data_json: client_data_json
        )

        expect(response.valid?(original_challenge, original_origin)).to be_falsy
      end
    end
  end
end
