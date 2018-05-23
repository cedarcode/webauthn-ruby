# frozen_string_literal: true

require "webauthn/authenticator_attestation_response"

RSpec.describe WebAuthn::AuthenticatorAttestationResponse do
  it "can validate none attestation" do
    original_challenge = seeds[:security_key][:credential_creation_options][:challenge]
    response = seeds[:security_key][:authenticator_attestation_response]

    response = WebAuthn::AuthenticatorAttestationResponse.new(
      attestation_object: response[:attestation_object],
      client_data_json: response[:client_data_json]
    )

    expect(response.valid?(original_challenge)).to eq(true)
  end

  it "can validate fido-u2f attestation" do
    original_challenge = seeds[:security_key_direct][:credential_creation_options][:challenge]
    response = seeds[:security_key_direct][:authenticator_attestation_response]

    response = WebAuthn::AuthenticatorAttestationResponse.new(
      attestation_object: response[:attestation_object],
      client_data_json: response[:client_data_json]
    )

    expect(response.valid?(original_challenge)).to eq(true)
  end

  it "returns user-friendly error if no client data received" do
    response = WebAuthn::AuthenticatorAttestationResponse.new(
      attestation_object: "",
      client_data_json: nil
    )

    expect {
      response.valid?("")
    }.to raise_exception(RuntimeError, "Missing client_data_json")
  end
end
