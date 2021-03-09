# frozen_string_literal: true

require "spec_helper"

RSpec.describe "FakeClient" do
  let(:client) { WebAuthn::FakeClient.new }

  context "#get" do
    let!(:credential_1) { client.create }
    let!(:credential_2) { client.create }

    it "returns the first matching credential when allow_credentials is nil" do
      assertion = client.get
      expect(assertion["id"]).to eq(credential_1["id"])
    end

    it "returns the matching credential when allow_credentials is passed" do
      allow_credentials = [credential_2["id"]]
      assertion = client.get(allow_credentials: allow_credentials)
      expect(assertion["id"]).to eq(credential_2["id"])
    end

    it "raises an error when no matching allow_credential can be found" do
      # base64(abc) is surely not a valid credential id (too short)
      allow_credentials = ["YWJj"]
      expect { client.get(allow_credentials: allow_credentials) }.to \
        raise_error(RuntimeError, /No matching credentials \(allowed=\["abc"\]\) found for RP/)
    end
  end
end
