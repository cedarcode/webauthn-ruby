# frozen_string_literal: true

require "spec_helper"

require "openssl"
require "webauthn/attestation_statement/apple"

RSpec.describe "Apple attestation" do
  describe "#valid?" do
    let(:credential_key) { create_ec_key }
    let(:root_key) { create_ec_key }
    let(:root_certificate) { create_root_certificate(root_key) }

    let(:cred_cert) do
      issue_certificate(root_certificate, root_key, credential_key, extensions: [cred_cert_extension])
    end

    let(:statement) { WebAuthn::AttestationStatement::Apple.new("x5c" => [cred_cert.to_der]) }

    let(:authenticator_data_bytes) do
      WebAuthn::FakeAuthenticator::AuthenticatorData.new(
        rp_id_hash: OpenSSL::Digest.digest("SHA256", "RP"),
        credential: { id: "0".b * 16, public_key: credential_key.public_key }
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

    around do |example|
      silence_warnings do
        original_apple_certificate = WebAuthn::AttestationStatement::Apple::ROOT_CERTIFICATE
        WebAuthn::AttestationStatement::Apple::ROOT_CERTIFICATE = root_certificate
        example.run
        WebAuthn::AttestationStatement::Apple::ROOT_CERTIFICATE = original_apple_certificate
      end
    end

    it "works if everything's fine" do
      expect(statement.valid?(authenticator_data, client_data_hash)).to be_truthy
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
