# frozen_string_literal: true

RSpec.describe WebAuthn do
  it "has a version number" do
    expect(WebAuthn::VERSION).not_to be nil
  end

  describe "#credential_creation_options" do
    before do
      @credential_creation_options = WebAuthn.credential_creation_options
    end

    it "has a 16 byte length challenge" do
      original_challenge = Base64.strict_decode64(@credential_creation_options[:challenge])
      expect(original_challenge.length).to eq(16)
    end

    it "has public key params" do
      expect(@credential_creation_options[:pubKeyCredParams][0][:type]).to eq("public-key")
      expect(@credential_creation_options[:pubKeyCredParams][0][:alg]).to eq(-7)
    end

    it "has relying party info" do
      expect(@credential_creation_options[:rp][:name]).to eq("web-server")
    end

    it "has user info" do
      user_info = @credential_creation_options[:user]
      expect(user_info[:name]).to eq("web-user")
      expect(user_info[:displayName]).to eq("web-user")
      expect(user_info[:id]).to eq("MQ==")
    end
  end

  describe "#credential_request_options" do
    let(:credential_request_options) { WebAuthn.credential_request_options }

    it "has a 16 byte length challenge" do
      original_challenge = Base64.strict_decode64(credential_request_options[:challenge])
      expect(original_challenge.length).to eq(16)
    end

    it "has allowCredentials param with an empty array" do
      expect(credential_request_options[:allowCredentials]).to match_array([])
    end
  end
end
