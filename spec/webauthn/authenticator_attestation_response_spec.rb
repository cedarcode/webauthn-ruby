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
