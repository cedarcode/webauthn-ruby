# frozen_string_literal: true

require "spec_helper"
require "webauthn/credential_request_options"

RSpec.describe WebAuthn::CredentialRequestOptions do
  let(:request_options) { WebAuthn::CredentialRequestOptions.new }

  it "has a challenge" do
    expect(request_options.challenge.class).to eq(String)
    expect(request_options.challenge.encoding).to eq(Encoding::ASCII_8BIT)
    expect(request_options.challenge.length).to eq(32)
  end

  it "has allowCredentials param with an empty array" do
    expect(request_options.allow_credentials).to match_array([])
  end
end
