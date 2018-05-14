RSpec.describe WebAuthn do
  it "has a version number" do
    expect(WebAuthn::VERSION).not_to be nil
  end

  it "has a 16 byte length challenge" do
    payload = WebAuthn.registration_payload

    expect(payload[:publicKey][:challenge].length).to eq(16)
  end

  it "has public key params" do
    payload = WebAuthn.registration_payload

    expect(payload[:publicKey][:pubKeyCredParams][0][:type]).to eq("public-key")
    expect(payload[:publicKey][:pubKeyCredParams][0][:alg]).to eq(-7)
  end

  it "has relying party info" do
    payload = WebAuthn.registration_payload

    expect(payload[:publicKey][:rp][:name]).to eq("web-server")
  end

  it "has user info" do
    payload = WebAuthn.registration_payload

    user_info = payload[:publicKey][:user]
    expect(user_info[:name]).to eq("web-user")
    expect(user_info[:displayName]).to eq("web-user")
    expect(user_info[:id]).to eq("MQ==\n")
  end
end
