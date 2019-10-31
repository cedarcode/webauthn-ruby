# frozen_string_literal: true

require "spec_helper"
require "webauthn/metadata/coercer/escaped_uri"

RSpec.describe WebAuthn::Metadata::Coercer::EscapedURI do
  subject { described_class.coerce(value) }

  context "when the value is a URI" do
    let(:value) { URI("https://github.com/cedarcode/webauthn-ruby") }

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
    context "containing a hex-encoded # character" do
      let(:value) { "https://github.com/cedarcode/webauthn-ruby%x23readme" }

      it "unescapes the # character and returns an URI" do
        expect(subject).to eq(URI("https://github.com/cedarcode/webauthn-ruby#readme"))
      end
    end

    context "not containing a hex-encoded # character" do
      let(:value) { "https://github.com/cedarcode/webauthn-ruby" }

      it "returns an URI" do
        expect(subject).to eq(URI("https://github.com/cedarcode/webauthn-ruby"))
      end
    end
  end
end
