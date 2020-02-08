# frozen_string_literal: true

require "spec_helper"

require "base64"
require "jwt"
require "openssl"
require "webauthn/attestation_statement/android_safetynet"

RSpec.describe WebAuthn::AttestationStatement::AndroidSafetynet do
  describe "#valid?" do
    let(:statement) { described_class.new("ver" => version, "response" => response) }
    let(:version) { "2.0" }

    let(:response) do
      JWT.encode(
        payload,
        attestation_key,
        "RS256",
        x5c: [Base64.strict_encode64(leaf_certificate.to_der)]
      )
    end

    let(:payload) do
      { "nonce" => nonce, "ctsProfileMatch" => cts_profile_match, "timestampMs" => timestamp.to_i * 1000 }
    end
    let(:timestamp) { Time.now }
    let(:cts_profile_match) { true }
    let(:nonce) { Base64.strict_encode64(OpenSSL::Digest::SHA256.digest(authenticator_data_bytes + client_data_hash)) }
    let(:attestation_key) { create_rsa_key }

    let(:leaf_certificate) do
      certificate = OpenSSL::X509::Certificate.new
      certificate.subject = OpenSSL::X509::Name.new([["CN", "attest.android.com"]])
      certificate.not_before = Time.now
      certificate.not_after = Time.now + 60
      certificate.issuer = root_certificate.subject
      certificate.public_key = attestation_key.public_key
      certificate.sign(root_key, OpenSSL::Digest::SHA256.new)
      certificate
    end

    let(:root_key) { OpenSSL::PKey::EC.new("prime256v1").generate_key }

    let(:root_certificate) do
      certificate = OpenSSL::X509::Certificate.new
      certificate.subject = OpenSSL::X509::Name.parse("/DC=org/DC=fake-ca/CN=Fake CA")
      certificate.issuer = certificate.subject
      certificate.public_key = root_key
      certificate.not_before = Time.now
      certificate.not_after = Time.now + 60

      extension_factory = OpenSSL::X509::ExtensionFactory.new
      extension_factory.subject_certificate = certificate
      extension_factory.issuer_certificate = certificate
      certificate.extensions = [
        extension_factory.create_extension("basicConstraints", "CA:TRUE", true),
        extension_factory.create_extension("keyUsage", "keyCertSign,cRLSign", true),
      ]

      certificate.sign(root_key, OpenSSL::Digest::SHA256.new)
      certificate
    end

    let(:authenticator_data) { WebAuthn::AuthenticatorData.deserialize(authenticator_data_bytes) }

    let(:authenticator_data_bytes) do
      WebAuthn::FakeAuthenticator::AuthenticatorData.new(
        rp_id_hash: OpenSSL::Digest::SHA256.digest("RP"),
        credential: { id: "0".b * 16, public_key: credential_key.public_key },
      ).serialize
    end

    let(:credential_key) { create_rsa_key }
    let(:client_data_hash) { OpenSSL::Digest::SHA256.digest({}.to_json) }

    before do
      allow(statement).to receive(:attestation_root_certificates).and_return([root_certificate])
    end

    it "returns true when everything's in place" do
      expect(statement.valid?(authenticator_data, client_data_hash)).to be_truthy
    end

    context "when nonce is not set to the base64 of the SHA256 of authData + clientDataHash" do
      let(:nonce) { Base64.strict_encode64(OpenSSL::Digest::SHA256.digest("something else")) }

      it "returns false" do
        expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
      end
    end

    context "when ctsProfileMatch is not true" do
      let(:cts_profile_match) { false }

      it "returns false" do
        expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
      end
    end
  end
end
