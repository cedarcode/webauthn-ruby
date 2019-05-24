# frozen_string_literal: true

require "spec_helper"
require "webauthn/credential_creation_options"

RSpec.describe WebAuthn::CredentialCreationOptions do
  let(:creation_options) do
    WebAuthn::CredentialCreationOptions.new(user_id: "1", user_name: "User", user_display_name: "User Display")
  end

  it "has a challenge" do
    expect(creation_options.challenge.class).to eq(String)
    expect(creation_options.challenge.encoding).to eq(Encoding::ASCII_8BIT)
    expect(creation_options.challenge.length).to eq(32)
  end

  context "public key params" do
    it "has default public key params" do
      params = creation_options.pub_key_cred_params

      expect(params.class).to eq(Array)
      expect(params.length).to eq(2)

      expect(params).to include(type: "public-key", alg: -7)
      expect(params).to include(type: "public-key", alg: -257)
    end

    context "when extra alg added" do
      before do
        WebAuthn.configuration.algorithms << "RS1"
      end

      it "is added to public key params" do
        params = creation_options.pub_key_cred_params

        expect(params.class).to eq(Array)
        expect(params.length).to eq(3)

        expect(params).to include(type: "public-key", alg: -7)
        expect(params).to include(type: "public-key", alg: -257)
        expect(params).to include(type: "public-key", alg: -65535)
      end
    end
  end

  context "Relying Party info" do
    it "has relying party name default" do
      expect(creation_options.rp.name).to eq("web-server")
    end

    context "when configured" do
      before do
        WebAuthn.configuration.rp_name = "Example Inc."
      end

      it "has the configured values" do
        expect(creation_options.rp.name).to eq("Example Inc.")
      end
    end
  end

  it "has user info" do
    expect(creation_options.user.id).to eq("1")
    expect(creation_options.user.name).to eq("User")
    expect(creation_options.user.display_name).to eq("User Display")
  end
end
