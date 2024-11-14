# frozen_string_literal: true

require "spec_helper"
require "webauthn/public_key_credential/request_options"

RSpec.describe WebAuthn::PublicKeyCredential::RequestOptions do
  let(:request_options) { WebAuthn::PublicKeyCredential::RequestOptions.new }

  it "has a challenge" do
    expect(request_options.challenge.class).to eq(String)
    expect(request_options.challenge.encoding).to eq(Encoding::ASCII)
    expect(request_options.challenge.length).to be >= 32
  end

  it "has allowCredentials param with an empty array" do
    expect(request_options.allow_credentials).to match_array([])
  end

  context "client timeout" do
    it "has a default client timeout" do
      expect(request_options.timeout).to(eq(120000))
    end

    context "when client timeout is configured" do
      before do
        WebAuthn.configuration.credential_options_timeout = 60000
      end

      it "updates the client timeout" do
        expect(request_options.timeout).to(eq(60000))
      end
    end
  end

  context "Relying Party info" do
    it "has relying party name default to nothing" do
      expect(request_options.rp_id).to eq(nil)
    end

    context "when configured" do
      before do
        WebAuthn.configuration.rp_id = "example.com"
      end

      it "has the configured values" do
        expect(request_options.rp_id).to eq("example.com")
      end
    end
  end

  it "has everything" do
    options = WebAuthn::PublicKeyCredential::RequestOptions.new(
      rp_id: "rp-id",
      timeout: 10_000,
      allow_credentials: [{ type: "public-key", id: "credential-id", transports: ["usb", "nfc"] }],
      user_verification: "required",
      extensions: { whatever: "whatever" },
    )

    hash = options.as_json

    expect(hash[:rpId]).to eq("rp-id")
    expect(hash[:timeout]).to eq(10_000)
    expect(hash[:allowCredentials]).to eq([{ type: "public-key", id: "credential-id", transports: ["usb", "nfc"] }])
    expect(hash[:userVerification]).to eq("required")
    expect(hash[:extensions]).to eq(whatever: "whatever")
    expect(hash[:challenge]).to be_truthy
  end

  it "has minimum required" do
    options = WebAuthn::PublicKeyCredential::RequestOptions.new

    hash = options.as_json

    expect(hash[:timeout]).to eq(120_000)
    expect(hash[:allowCredentials]).to eq([])
    expect(hash[:extensions]).to eq({})
    expect(hash[:challenge]).to be_truthy
    expect(hash).not_to have_key(:userVerification)
    expect(hash).not_to have_key(:rpId)
  end

  it "accepts shorthand for allow_credentials" do
    options = WebAuthn::PublicKeyCredential::RequestOptions.new(allow: "id")

    expect(options.allow).to eq("id")
    expect(options.allow_credentials).to eq([{ type: "public-key", id: "id" }])
    expect(options.as_json[:allowCredentials]).to eq([{ type: "public-key", id: "id" }])
  end

  context "when legacy_u2f_appid" do
    context "is set in the configuration" do
      before do
        WebAuthn.configuration.legacy_u2f_appid = "https://u2f-login.example.com"
      end

      context "and appid extension is not requested in the options" do
        it "automatically adds it with the value in the configuration" do
          expect(request_options.extensions).not_to be_empty
          expect(request_options.extensions[:appid]).to eq("https://u2f-login.example.com")
        end
      end

      context "and appid extension is requested in the options" do
        let(:request_options) do
          WebAuthn::PublicKeyCredential::RequestOptions.new(
            extensions: { appid: "https://another-login.example.com" }
          )
        end

        it "leaves the value that was originally requested" do
          expect(request_options.extensions).not_to be_empty
          expect(request_options.extensions[:appid]).to eq("https://another-login.example.com")
        end
      end
    end

    context "is not set in the configuration" do
      context "and appid extension is not requested in the options" do
        it "does not adds it automatically" do
          expect(request_options.extensions).to be_empty
        end
      end

      context "and appid extension is requested in the options" do
        let(:request_options) do
          WebAuthn::PublicKeyCredential::RequestOptions.new(
            extensions: { appid: "https://another-login.example.com" }
          )
        end

        it "leaves the value that was originally requested" do
          expect(request_options.extensions).not_to be_empty
          expect(request_options.extensions[:appid]).to eq("https://another-login.example.com")
        end
      end
    end
  end
end
