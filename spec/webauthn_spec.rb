# frozen_string_literal: true

require "spec_helper"

RSpec.describe WebAuthn do
  it "has a version number" do
    expect(WebAuthn::VERSION).not_to be nil
  end

  describe "#credential_creation_options" do
    before do
      @credential_creation_options = WebAuthn.credential_creation_options
    end

    it "has a 32 byte length challenge" do
      expect(@credential_creation_options[:challenge].length).to eq(32)
    end

    it "has public key params" do
      params = @credential_creation_options[:pubKeyCredParams]

      array = if OpenSSL::PKey::RSA.instance_methods.include?(:verify_pss)
                [
                  { type: "public-key", alg: -7 },
                  { type: "public-key", alg: -37 },
                  { type: "public-key", alg: -257 },
                ]
              else
                [
                  { type: "public-key", alg: -7 },
                  { type: "public-key", alg: -257 },
                ]
              end

      expect(params).to match_array(array)
    end

    it "has user info" do
      user_info = @credential_creation_options[:user]
      expect(user_info[:name]).to eq("web-user")
      expect(user_info[:displayName]).to eq("web-user")
      expect(user_info[:id]).to eq("1")
    end

    context "Relying Party info" do
      it "has relying party name default" do
        expect(@credential_creation_options[:rp][:name]).to eq("web-server")
      end

      context "when configured" do
        before do
          WebAuthn.configuration.rp_name = "Example Inc."
        end

        it "has the configured values" do
          creation_options = WebAuthn.credential_creation_options

          expect(creation_options[:rp][:name]).to eq("Example Inc.")
        end
      end
    end
  end

  describe "#credential_request_options" do
    let(:credential_request_options) { WebAuthn.credential_request_options }

    it "has a 32 byte length challenge" do
      expect(credential_request_options[:challenge].length).to eq(32)
    end

    it "has allowCredentials param with an empty array" do
      expect(credential_request_options[:allowCredentials]).to match_array([])
    end
  end
end
