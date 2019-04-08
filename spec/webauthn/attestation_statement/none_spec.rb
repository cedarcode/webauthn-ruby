# frozen_string_literal: true

require "spec_helper"

require "webauthn/attestation_statement/none"

RSpec.describe "none attestation" do
  describe "#valid?" do
    it "returns true if the statement is an empty map" do
      expect(WebAuthn::AttestationStatement::None.new({}).valid?).to be_truthy
    end

    it "returns false if the statement is something else" do
      expect(WebAuthn::AttestationStatement::None.new(nil).valid?).to be_falsy
      expect(WebAuthn::AttestationStatement::None.new("").valid?).to be_falsy
      expect(WebAuthn::AttestationStatement::None.new([]).valid?).to be_falsy
      expect(WebAuthn::AttestationStatement::None.new("something" => "here").valid?).to be_falsy
    end
  end
end
