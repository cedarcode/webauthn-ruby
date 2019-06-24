# frozen_string_literal: true

require "spec_helper"
require "support/seeds"
require "byebug"

require "webauthn/u2f_migrator"

RSpec.describe WebAuthn::U2fMigrator do
  let(:stored_credential) { seeds[:u2f_migration][:stored_credential] }
  let(:app_id) { URI("https://f69df4d9.ngrok.io") }

  subject do
    described_class.new(
      app_id: app_id,
      certificate: stored_credential[:certificate],
      key_handle: stored_credential[:key_handle],
      public_key: stored_credential[:public_key],
      counter: 41
    )
  end

  it "returns the credential ID" do
    expect(Base64.strict_encode64(subject.credential.id))
      .to eq("1a9tIwwYiYNdmfmxVaksOkxKapK2HtDNSsL4MssbCHILhkMzA0xZYk5IHmBljyblTQ/SnsQea+QEMzgTN2L1Mw==")
  end

  it "returns the credential public key in COSE format" do
    public_key = COSE::Key.deserialize(subject.credential.public_key)

    expect(public_key.alg).to eq(-7)
    expect(public_key.crv).to eq(1)
    expect(public_key.x).to eq(Base64.strict_decode64("FtOd9t3mxj6sLFkNCLzv5qS9l52MipHznrsZ+uwtHQY="))
    expect(public_key.y).to eq(Base64.strict_decode64("np4zBpD5zhdSq1wKPvhzEoKJvFuYel1cpdTCzpahrBA="))
  end

  it "returns the signature counter" do
    expect(subject.authenticator_data.sign_count).to eq(41)
  end

  it "returns the 'Basic or AttCA' attestation type" do
    expect(subject.attestation_type).to eq("Basic_or_AttCA")
  end

  it "returns the attestation certificate" do
    certificate = subject.attestation_trust_path.first

    expect(certificate.subject.to_s).to eq("/CN=U2F Device")
    expect(certificate.issuer.to_s).to eq("/CN=U2F Issuer")
  end
end
