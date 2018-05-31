# frozen_string_literal: true

require "webauthn/authenticator_assertion_response"

RSpec.describe WebAuthn::AuthenticatorAssertionResponse do
  let(:challenge) { fake_challenge }
  let(:encoded_challenge) { WebAuthn::Utils.ua_encode(challenge) }
  let(:original_origin) { fake_origin }

  it "is valid if everything's in place" do
    assertion_response = WebAuthn::AuthenticatorAssertionResponse.new(
      client_data_json: encoded_fake_client_data_json(challenge: challenge,
                                                      origin: original_origin,
                                                      type: "webauthn.get"),
      authenticator_data: fake_authenticator_data
    )

    expect(assertion_response.valid?(encoded_challenge, original_origin)).to be_truthy
  end

  describe "type validation" do
    it "is invalid if type is not get" do
      assertion_response = WebAuthn::AuthenticatorAssertionResponse.new(
        client_data_json: encoded_fake_client_data_json(challenge: challenge,
                                                        origin: original_origin,
                                                        type: "webauthn.create"),
        authenticator_data: fake_authenticator_data
      )

      expect(assertion_response.valid?(encoded_challenge, original_origin)).to be_falsy
    end
  end

  describe "user present validation" do
    it "is invalid if user-present flag is off" do
      assertion_response = WebAuthn::AuthenticatorAssertionResponse.new(
        client_data_json: encoded_fake_client_data_json(challenge: challenge,
                                                        origin: original_origin,
                                                        type: "webauthn.get"),
        authenticator_data: fake_authenticator_data(user_present: false)
      )

      expect(assertion_response.valid?(encoded_challenge, original_origin)).to be_falsy
    end
  end

  describe "challenge validation" do
    it "is invalid if challenge doesn't match" do
      original_challenge = fake_challenge
      encoded_original_challenge = WebAuthn::Utils.ua_encode(original_challenge)

      assertion_response = WebAuthn::AuthenticatorAssertionResponse.new(
        client_data_json: encoded_fake_client_data_json(challenge: challenge,
                                                        origin: original_origin,
                                                        type: "webauthn.get"),
        authenticator_data: fake_authenticator_data
      )

      expect(assertion_response.valid?(encoded_original_challenge, original_origin)).to be_falsy
    end
  end

  describe "origin validation" do
    it "is invalid if origin doesn't match" do
      assertion_response = WebAuthn::AuthenticatorAssertionResponse.new(
        client_data_json: encoded_fake_client_data_json(challenge: challenge,
                                                        origin: original_origin,
                                                        type: "webauthn.get"),
        authenticator_data: fake_authenticator_data
      )

      expect(assertion_response.valid?(encoded_challenge, "http://different-origin")).to be_falsy
    end
  end
end
