# frozen_string_literal: true

require "webauthn/authenticator_assertion_response"

RSpec.describe WebAuthn::AuthenticatorAssertionResponse do
  it "is invalid if type is not get" do
    assertion_response = WebAuthn::AuthenticatorAssertionResponse.new(
      client_data_json: hash_to_encoded_json(type: "webauthn.create"),
      authenticator_data: fake_authenticator_data
    )

    expect(assertion_response.valid?).to be_falsy
  end

  it "is invalid if user-present flag is off" do
    assertion_response = WebAuthn::AuthenticatorAssertionResponse.new(
      client_data_json: hash_to_encoded_json(type: "webauthn.get"),
      authenticator_data: fake_authenticator_data(user_present: false)
    )

    expect(assertion_response.valid?).to be_falsy
  end

  it "is valid if everythings in place" do
    assertion_response = WebAuthn::AuthenticatorAssertionResponse.new(
      client_data_json: hash_to_encoded_json(type: "webauthn.get"),
      authenticator_data: fake_authenticator_data
    )

    expect(assertion_response.valid?).to be_truthy
  end
end
