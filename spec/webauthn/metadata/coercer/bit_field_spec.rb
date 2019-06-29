# frozen_string_literal: true

require "spec_helper"
require "webauthn/metadata/coercer/bit_field"

RSpec.describe WebAuthn::Metadata::Coercer::BitField do
  CONSTANTS = {
    0b0001 => "foo",
    0b0010 => "bar",
    0b0100 => "baz",
  }.freeze

  context "multiple values" do
    subject { described_class.new(CONSTANTS, single_value: false).coerce(value) }

    context "when the flag is not known" do
      let(:value) { 0b1000 }

      it "returns an empty array" do
        expect(subject).to be_empty
      end
    end

    context "when flags are known" do
      let(:value) { 0b0011 }

      it "returns an array with the values" do
        expect(subject).to match_array(["foo", "bar"])
      end
    end
  end

  context "single value" do
    subject { described_class.new(CONSTANTS, single_value: true).coerce(value) }

    context "when the flag is not known" do
      let(:value) { 0b1000 }

      it "returns an empty array" do
        expect(subject).to be_nil
      end
    end

    context "when flags are known" do
      let(:value) { 0b0001 }

      it "returns an array with the values" do
        expect(subject).to eq("foo")
      end
    end
  end
end
