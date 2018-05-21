RSpec.describe WebAuthn do
  it "has a version number" do
    expect(WebAuthn::VERSION).not_to be nil
  end

  describe "#registration_payload" do
    before do
      @payload = WebAuthn.registration_payload
    end

    it "has a 16 byte length challenge" do
      expect(@payload[:publicKey][:challenge].length).to eq(16)
    end

    it "has public key params" do
      expect(@payload[:publicKey][:pubKeyCredParams][0][:type]).to eq("public-key")
      expect(@payload[:publicKey][:pubKeyCredParams][0][:alg]).to eq(-7)
    end

    it "has relying party info" do
      expect(@payload[:publicKey][:rp][:name]).to eq("web-server")
    end

    it "has user info" do
      user_info = @payload[:publicKey][:user]
      expect(user_info[:name]).to eq("web-user")
      expect(user_info[:displayName]).to eq("web-user")
      expect(user_info[:id]).to eq("MQ==\n")
    end
  end

  describe "#valid?" do
    it "validates registration attestation" do
      client_data_bin = 'eyJjaGFsbGVuZ2UiOiJTSm9xeFhTWkFsRWxCZlNhMTFEdFpRIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9'

      valid = WebAuthn.valid?(client_data_bin: client_data_bin)

      expect(valid).to eq(true)
    end
  end
end
