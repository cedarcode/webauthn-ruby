# frozen_string_literal: true

require "spec_helper"
require "webauthn/metadata/coercer/user_verification_details"

RSpec.describe WebAuthn::Metadata::Coercer::UserVerificationDetails do
  subject { described_class.coerce(value) }

  context "when the value is an array of array of VerificationMethodDescriptor" do
    let(:value) do
      [
        [WebAuthn::Metadata::VerificationMethodDescriptor.new]
      ]
    end

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

  context "when the value is an array of String" do
    let(:support_path) { Pathname.new(File.expand_path(File.join(__dir__, "..", "..", "..", "support"))) }
    let(:file) { File.read(support_path.join("mds_user_verification_methods.json")) }
    let(:value) { JSON.parse(file) }

    it "returns an array of array of VerificationMethodDescriptor" do
      expect(subject).to include(
        a_collection_containing_exactly(
          kind_of(WebAuthn::Metadata::VerificationMethodDescriptor)
        )
      )
      expect(subject[0][0].ba_desc).to be_a(WebAuthn::Metadata::BiometricAccuracyDescriptor)
      expect(subject[1][0].ca_desc).to be_a(WebAuthn::Metadata::CodeAccuracyDescriptor)
    end
  end
end
