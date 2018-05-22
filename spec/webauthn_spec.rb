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
      original_challenge = Base64.urlsafe_decode64(@credential_creation_options[:challenge])
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

  describe "#valid?" do
    it "validates registration attestation" do
      original_challenge = security_key_challenge
      response = security_key_response

      valid = WebAuthn.valid?(
        original_challenge: original_challenge,
        attestation_object: response[:attestation_object],
        client_data_bin: response[:client_data_bin]
      )

      expect(valid).to eq(true)
    end
  end
end
