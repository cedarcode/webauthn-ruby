# frozen_string_literal: true

require "spec_helper"

require "base64"
require "jwt"
require "openssl"
require "webauthn/attestation_statement/android_safetynet"

RSpec.describe "android-safetynet attestation" do
  describe "#valid?" do
    let(:statement) { WebAuthn::AttestationStatement::AndroidSafetynet.new("ver" => version, "response" => response) }
    let(:version) { "2.0" }

    let(:response) do
      JWT.encode(
        payload,
        attestation_key,
        "ES256",
        x5c: [Base64.strict_encode64(leaf_certificate)]
      )
    end

    let(:payload) { { "nonce" => nonce, "ctsProfileMatch" => cts_profile_match } }
    let(:cts_profile_match) { true }
    let(:nonce) { Base64.strict_encode64(OpenSSL::Digest::SHA256.digest(authenticator_data_bytes + client_data_hash)) }
    let(:attestation_key) { OpenSSL::PKey::EC.new("prime256v1").generate_key }

    let(:leaf_certificate) do
      certificate = OpenSSL::X509::Certificate.new
      certificate.subject = OpenSSL::X509::Name.new([["CN", "attest.android.com"]])
      certificate.not_before = Time.now
      certificate.not_after = Time.now + 60
      certificate.public_key = attestation_key

      certificate.sign(attestation_key, OpenSSL::Digest::SHA256.new)

      certificate.to_der
    end

    let(:authenticator_data) { WebAuthn::AuthenticatorData.new(authenticator_data_bytes) }

    let(:authenticator_data_bytes) do
      WebAuthn::FakeAuthenticator::AuthenticatorData.new(
        rp_id_hash: OpenSSL::Digest::SHA256.digest("RP"),
        credential: { id: "0".b * 16, public_key: credential_key.public_key },
      ).serialize
    end

    let(:credential_key) { OpenSSL::PKey::EC.new("prime256v1").generate_key }
    let(:client_data_hash) { OpenSSL::Digest::SHA256.digest({}.to_json) }

    before do
      # TODO: Test attestation cert chain validation
      allow(statement).to receive(:trusted_attestation_certificate?).and_return(true)
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