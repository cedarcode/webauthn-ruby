# frozen_string_literal: true

require "spec_helper"

require "webauthn/attestation_statement/none"

RSpec.describe "none attestation" do
  let(:authenticator_data_bytes) do
    WebAuthn::FakeAuthenticator::AuthenticatorData.new(
      rp_id_hash: OpenSSL::Digest.digest("SHA256", "localhost"),
      aaguid: 0.chr * 16,
    ).serialize
  end
  let(:authenticator_data) { WebAuthn::AuthenticatorData.deserialize(authenticator_data_bytes) }

  describe "#valid?" do
    it "returns true if the statement is an empty map" do
      expect(WebAuthn::AttestationStatement::None.new({}).valid?(authenticator_data, nil)).to be_truthy
    end

    it "returns attestation info" do
      attestation_statement = WebAuthn::AttestationStatement::None.new({})
      expect(attestation_statement.valid?(authenticator_data, nil)).to eq(
        ["None", nil]
      )
    end

    it "returns false if the statement is something else" do
      expect(WebAuthn::AttestationStatement::None.new(nil).valid?(authenticator_data, nil)).to be_falsy
      expect(WebAuthn::AttestationStatement::None.new("").valid?(authenticator_data, nil)).to be_falsy
      expect(WebAuthn::AttestationStatement::None.new([]).valid?(authenticator_data, nil)).to be_falsy
      expect(WebAuthn::AttestationStatement::None.new("a" => "b").valid?(authenticator_data, nil)).to be_falsy
    end

    it "returns false if None is not among the acceptable formats" do
      WebAuthn.configuration.acceptable_attestation_types = ['AttCA']

      expect(WebAuthn::AttestationStatement::None.new({}).valid?(authenticator_data, nil)).to be_falsy
    end
  end
end
