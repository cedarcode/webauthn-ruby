# frozen_string_literal: true

RSpec.describe WebAuthn::Validator do
  it "return user-friendly error if no client data received" do
    validator = WebAuthn::Validator.new(
      attestation_object: "",
      original_challenge: "",
      client_data_bin: nil
    )

    expect {
      validator.valid?
    }.to raise_exception(RuntimeError, "Missing client_data_bin")
  end

  it "validates fido-u2f attestation" do
    original_challenge = seeds[:security_key_direct][:credential_creation_options][:challenge]
    response = seeds[:security_key_direct][:authenticator_attestation_response]

    validator = WebAuthn::Validator.new(
      original_challenge: original_challenge,
      attestation_object: response[:attestation_object],
      client_data_bin: response[:client_data_json]
    )

    expect(validator.valid?).to eq(true)
  end
end
