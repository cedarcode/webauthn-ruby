# frozen_string_literal: true

require "spec_helper"

RSpec.describe WebAuthn::AuthenticatorData do
  let(:serialized_authenticator_data) do
    WebAuthn::FakeAuthenticator::AuthenticatorData.new(
      rp_id_hash: rp_id_hash,
      sign_count: sign_count,
      user_present: user_present,
      user_verified: user_verified
    ).serialize
  end

  let(:rp_id_hash) { OpenSSL::Digest::SHA256.digest("localhost") }
  let(:sign_count) { 42 }
  let(:user_present) { true }
  let(:user_verified) { false }

  let(:authenticator_data) { described_class.new(serialized_authenticator_data) }

  describe "#valid?" do
    it "returns true" do
      expect(authenticator_data.valid?).to be_truthy
    end

    it "returns false if leftover bytes" do
      data = WebAuthn::FakeAuthenticator::AuthenticatorData.new(
        rp_id_hash: rp_id_hash,
        sign_count: sign_count,
        user_present: user_present,
        user_verified: user_verified,
        extensions: nil
      ).serialize

      authenticator_data = WebAuthn::AuthenticatorData.new(data + CBOR.encode("k" => "v"))

      expect(authenticator_data.valid?).to be_falsy
    end
  end

  describe "#rp_id_hash" do
    subject { authenticator_data.rp_id_hash }
    it { is_expected.to eq(rp_id_hash) }
  end

  describe "#sign_count" do
    subject { authenticator_data.sign_count }
    it { is_expected.to eq(42) }
  end

  describe "#user_present?" do
    subject { authenticator_data.user_present? }

    context "when UP flag is set" do
      let(:user_present) { true }
      it { is_expected.to be_truthy }
    end

    context "when UP flag is not set" do
      let(:user_present) { false }
      it { is_expected.to be_falsy }
    end
  end

  describe "#user_verified?" do
    subject { authenticator_data.user_verified? }

    context "when UV flag is set" do
      let(:user_verified) { true }

      it { is_expected.to be_truthy }
    end

    context "when UV flag is not set" do
      let(:user_verified) { false }

      it { is_expected.to be_falsy }
    end
  end

  describe "#user_flagged?" do
    subject { authenticator_data.user_flagged? }

    context "when both UP and UV flag are set" do
      let(:user_present) { true }
      let(:user_verified) { true }

      it { is_expected.to be_truthy }
    end

    context "when only UP is set" do
      let(:user_present) { true }
      let(:user_verified) { false }

      it { is_expected.to be_truthy }
    end

    context "when only UV flag is set" do
      let(:user_present) { false }
      let(:user_verified) { true }

      it { is_expected.to be_truthy }
    end

    context "when both UP and UV flag are not set" do
      let(:user_present) { false }
      let(:user_verified) { false }

      it { is_expected.to be_falsy }
    end
  end
end
