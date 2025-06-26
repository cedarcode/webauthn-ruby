# frozen_string_literal: true

require "spec_helper"
require "support/seeds"
require "byebug"

require "webauthn/u2f_migrator"

RSpec.describe WebAuthn::U2fMigrator do
  subject(:u2f_migrator) do
    described_class.new(
      app_id: app_id,
      certificate: stored_credential[:certificate],
      key_handle: stored_credential[:key_handle],
      public_key: stored_credential[:public_key],
      counter: 41
    )
  end

  let(:stored_credential) { seeds[:u2f_migration][:stored_credential] }
  let(:app_id) { URI("https://example.org") }

  it "returns the credential ID" do
    expect(WebAuthn::Encoders::Base64Encoder.encode(u2f_migrator.credential.id))
      .to eq("pLpuLSz+xDZI19JcXtVlm8GPK3gVOFJ+vUkt4DJWvfQ=")
  end

  it "returns the credential public key in COSE format" do
    public_key = COSE::Key.deserialize(u2f_migrator.credential.public_key)

    expect(public_key.alg).to eq(-7)
    expect(public_key.crv).to eq(1)
    expect(public_key.x).to eq(WebAuthn::Encoders::Base64Encoder.decode("sNYt5rMPhvC6x6kBaVE5HC4xhJ4uZGYcvSsTzX1VCK0="))
    expect(public_key.y).to eq(WebAuthn::Encoders::Base64Encoder.decode("UDsL2io1eppLNEdaKOZbZgtImKnj6bvwgg1DSUKX7dA="))
  end

  it "returns the signature counter" do
    expect(u2f_migrator.authenticator_data.sign_count).to eq(41)
  end

  it "returns the 'Basic or AttCA' attestation type" do
    expect(u2f_migrator.attestation_type).to eq("Basic_or_AttCA")
  end

  it "returns the attestation certificate" do
    certificate = u2f_migrator.attestation_trust_path.first

    expect(certificate.subject.to_s).to eq("/CN=WebAuthn test vectors/O=W3C/OU=Authenticator Attestation/C=AA")
    expect(certificate.issuer.to_s).to eq("/CN=WebAuthn test vectors/O=W3C/OU=Authenticator Attestation CA/C=AA")
  end
end
