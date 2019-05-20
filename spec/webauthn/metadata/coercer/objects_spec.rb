# frozen_string_literal: true

require "spec_helper"
require "webauthn/metadata/entry"
require "webauthn/metadata/coercer/objects"

RSpec.describe WebAuthn::Metadata::Coercer::Objects do
  subject { described_class.new(WebAuthn::Metadata::Entry).coerce(value) }

  context "when the value is an array of Entry" do
    let(:value) { [WebAuthn::Metadata::Entry.new] }

    it "returns the same value" do
      expect(subject).to eq(value)
    end
  end

  context "when the value is nil" do
    let(:value) { nil }

    specify do
      expect(subject).to be_nil
    end
  end

  context "when the value is an array of Hash" do
    let(:value) { [{ "aaguid" => "1234", "hash" => "abcde" }] }

    it "returns an array of Entry" do
      expect(subject).to all(be_a(WebAuthn::Metadata::Entry))
    end
  end
end
