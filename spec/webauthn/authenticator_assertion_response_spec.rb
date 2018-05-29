# frozen_string_literal: true

require "webauthn/authenticator_assertion_response"

RSpec.describe WebAuthn::AuthenticatorAssertionResponse do
  it "is invalid if type is not get" do
    assertion_response = WebAuthn::AuthenticatorAssertionResponse.new(
      client_data_json: hash_to_encoded_json(type: "webauthn.create")
    )

    expect(assertion_response.valid?).to be_falsy
  end

  it "is valid if everythings in place" do
    assertion_response = WebAuthn::AuthenticatorAssertionResponse.new(
      client_data_json: hash_to_encoded_json(type: "webauthn.get")
    )

    expect(assertion_response.valid?).to be_truthy
  end
end
