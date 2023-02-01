# frozen_string_literal: true

require "spec_helper"

require "openssl"
require "webauthn/attestation_statement/apple_app"

RSpec.describe "Apple App attestation" do
  describe "#valid?" do
    let(:credential_key) { create_ec_key }
    let(:root_key) { create_ec_key }
    let(:root_certificate) { create_root_certificate(root_key) }

    let(:leaf_certificate) do
      issue_certificate(root_certificate, root_key, attestation_key, name: "CN=TODO.apple.com")
    end

    let(:cred_cert) do
      issue_certificate(root_certificate, root_key, credential_key, extensions: [cred_cert_extension])
    end

    let(:statement) { WebAuthn::AttestationStatement::AppleApp.new("x5c" => [cred_cert.to_der]) }

    let(:apple_aaguid) { 'appattestdevelop' }
    let(:development_mode) { true }
    let(:sign_count) { 0 }
    let(:authenticator_data_bytes) do
      WebAuthn::FakeAuthenticator::AuthenticatorData.new(
        rp_id_hash: OpenSSL::Digest.digest("SHA256", "RP"),
        credential: { id: "0".b * 16, public_key: credential_key.public_key },
        aaguid: apple_aaguid,
        sign_count: sign_count
      ).serialize
    end

    let(:authenticator_data) { WebAuthn::AuthenticatorData.deserialize(authenticator_data_bytes) }
    let(:client_data_hash) { OpenSSL::Digest::SHA256.digest({}.to_json) }

    let(:nonce) { Digest::SHA256.digest(authenticator_data.data + client_data_hash) }
    let(:cred_cert_extension) do
      OpenSSL::X509::Extension.new(
        "1.2.840.113635.100.8.2",
        OpenSSL::ASN1::Sequence.new(
          [OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::OctetString.new(nonce)])]
        )
      )
    end

    before do
      WebAuthn.configure do |config|
        config.rp_id = 'RP'
        config.development_mode = development_mode
      end
    end

    around do |example|
      silence_warnings do
        original_apple_certificate = WebAuthn::AttestationStatement::AppleApp::ROOT_CERTIFICATE
        WebAuthn::AttestationStatement::AppleApp::ROOT_CERTIFICATE = root_certificate
        example.run
        WebAuthn::AttestationStatement::AppleApp::ROOT_CERTIFICATE = original_apple_certificate
      end
    end

    it "works if everything's fine" do
      expect(statement.valid?(authenticator_data, client_data_hash)).to be_truthy
    end

    context "when production mode" do
      let(:development_mode) { false }
      let(:apple_aaguid) { "appattest\x00\x00\x00\x00\x00\x00\x00" }

      it { expect(statement.valid?(authenticator_data, client_data_hash)).to be_truthy }
    end

    context "when sign_count is not zero" do
      let(:sign_count) { 1 }

      it "fails" do
        expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
      end
    end

    context "when nonce is invalid" do
      let(:nonce) { Digest::SHA256.digest("Invalid") }

      it "fails" do
        expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
      end
    end

    context "when the credential public key is invalid" do
      let(:cred_cert) do
        issue_certificate(root_certificate, root_key, create_ec_key, extensions: [cred_cert_extension])
      end

      it "fails" do
        expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
      end
    end
  end
end
