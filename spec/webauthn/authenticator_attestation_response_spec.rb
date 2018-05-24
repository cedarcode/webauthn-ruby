# frozen_string_literal: true

require "webauthn/authenticator_attestation_response"

RSpec.describe WebAuthn::AuthenticatorAttestationResponse do
  it "can be validated" do
    original_challenge = seeds[:security_key][:credential_creation_options][:challenge]
    response = seeds[:security_key][:authenticator_attestation_response]

    response = WebAuthn::AuthenticatorAttestationResponse.new(
      attestation_object: response[:attestation_object],
      client_data_json: response[:client_data_json]
    )

    expect(response.valid?(original_challenge, "http://localhost:3000")).to eq(true)
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
    let(:challenge) { Base64.urlsafe_encode64(SecureRandom.random_bytes(16)) }
    let(:client_data_json) { hash_to_encoded_json(challenge: challenge,
                                                  clientExtensions: {},
                                                  hashAlgorithm: "SHA-256",
                                                  origin: origin,
                                                  type: "webauthn.create") }
    let(:auth_data) { [73, 150, 13, 229, 136, 14, 140, 104, 116, 52, 23, 15, 100,
                       118, 96, 91, 143, 228, 174, 185, 162, 134, 50, 199, 153,
                       92, 243, 186, 131, 29, 151, 99, 65, 0, 0, 0, 0].pack('c*') }
    let(:attestation_object) { hash_to_encoded_cbor(fmt: "none",
                                                    attStmt: {},
                                                    authData: auth_data) }

    context "matches the default one" do
      let(:origin) { "http://localhost" }

      it "is valid" do
        response = WebAuthn::AuthenticatorAttestationResponse.new(
          attestation_object: attestation_object,
          client_data_json: client_data_json
        )

        expect(response.valid?(challenge, original_origin)).to be_truthy
      end
    end

    context "doesn't match the default one" do
      let(:origin) { "http://invalid" }

      it "isn't valid" do
        response = WebAuthn::AuthenticatorAttestationResponse.new(
          attestation_object: attestation_object,
          client_data_json: client_data_json
        )

        expect(response.valid?(challenge, original_origin)).to be_falsy
      end
    end
  end

end
