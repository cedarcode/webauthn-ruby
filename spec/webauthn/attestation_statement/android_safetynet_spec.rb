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
      issue_certificate(root_certificate, root_key, attestation_key, name: "CN=attest.android.com")
    end

    let(:root_key) { create_ec_key }
    let(:root_certificate) { create_root_certificate(root_key) }
    let(:authenticator_data) { WebAuthn::AuthenticatorData.deserialize(authenticator_data_bytes) }

    let(:authenticator_data_bytes) do
      WebAuthn::FakeAuthenticator::AuthenticatorData.new(
        rp_id_hash: OpenSSL::Digest.digest("SHA256", "RP"),
        credential: { id: "0".b * 16, public_key: credential_key.public_key },
      ).serialize
    end

    let(:credential_key) { create_rsa_key }
    let(:client_data_hash) { OpenSSL::Digest::SHA256.digest({}.to_json) }

    let(:google_certificates) { [root_certificate] }

    around do |example|
      silence_warnings do
        original_google_certificates = SafetyNetAttestation::Statement::GOOGLE_ROOT_CERTIFICATES
        SafetyNetAttestation::Statement::GOOGLE_ROOT_CERTIFICATES = google_certificates
        example.run
        SafetyNetAttestation::Statement::GOOGLE_ROOT_CERTIFICATES = original_google_certificates
      end
    end

    it "returns true when everything's in place" do
      expect(statement.valid?(authenticator_data, client_data_hash)).to be_truthy
    end

    context "when nonce is not set to the base64 of the SHA256 of authData + clientDataHash" do
      let(:nonce) { Base64.strict_encode64(OpenSSL::Digest.digest("SHA256", "something else")) }

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

    context "when the attestation certificate is not signed by Google" do
      let(:google_certificates) { [create_root_certificate(create_ec_key)] }

      it "fails" do
        expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
      end

      it "returns true if they are configured" do
        WebAuthn.configuration.attestation_root_certificates_finders = finder_for(root_certificate)

        expect(statement.valid?(authenticator_data, client_data_hash)).to be_truthy
      end
    end
  end
end
