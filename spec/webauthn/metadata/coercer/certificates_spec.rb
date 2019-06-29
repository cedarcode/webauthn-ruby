# frozen_string_literal: true

require "spec_helper"
require "webauthn/metadata/coercer/certificates"

RSpec.describe WebAuthn::Metadata::Coercer::Certificates do
  subject { described_class.coerce(value) }

  context "when the value is an array of Certificate" do
    let(:value) { [OpenSSL::X509::Certificate.new] }

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
end
