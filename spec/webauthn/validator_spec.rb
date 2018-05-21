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
end
