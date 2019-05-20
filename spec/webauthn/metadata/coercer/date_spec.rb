# frozen_string_literal: true

require "spec_helper"
require "webauthn/metadata/coercer/date"

RSpec.describe WebAuthn::Metadata::Coercer::Date do
  subject { described_class.coerce(value) }

  context "when the value is a Date" do
    let(:value) { Date.new(2019, 5, 20) }

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

  context "when the value is a String" do
    context "containing a valid ISO-8601 value" do
      let(:value) { "2019-05-20" }

      specify do
        expect(subject).to be_a(Date)
      end
    end

    context "not containing an invalid ISO-8601 value" do
      let(:value) { "2019-20-05" }

      specify do
        expect { subject }.to raise_error(ArgumentError)
      end
    end
  end
end
