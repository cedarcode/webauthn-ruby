RSpec.describe WebAuthn do
  it "has a version number" do
    expect(WebAuthn::VERSION).not_to be nil
  end

  describe "#registration_payload" do
    before do
      @payload = WebAuthn.registration_payload
    end

    it "has a 16 byte length challenge" do
      original_challenge = Base64.urlsafe_decode64(@payload[:publicKey][:challenge])
      expect(original_challenge.length).to eq(16)
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
      expect(user_info[:id]).to eq("MQ==")
    end
  end

  describe "#valid?" do
    it "validates registration attestation" do
      original_challenge = 'SJoqxXSZAlElBfSa11DtZQ=='
      attestation_object = 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQPx8VO/e2RN8kYB4fx1r1JqiqxukuoebUJrb5LDjVhNX5qefpOiOsQ/GWvQDVnzF4AugvPs/WCUZ+tOp6hpmZp6lAQIDJiABIVggblr3cP0yKHKavNkN4R7AecQKZsRZriWO79Kgwzvon8MiWCBdEB+QtzhJj+HkkvQPbVxK+HUDNtkIIBmhqGquQrn6YQ=='
      client_data_bin = 'eyJjaGFsbGVuZ2UiOiJTSm9xeFhTWkFsRWxCZlNhMTFEdFpRIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9'

      valid = WebAuthn.valid?(
        original_challenge: original_challenge,
        attestation_object: attestation_object,
        client_data_bin: client_data_bin
      )

      expect(valid).to eq(true)
    end
  end
end
