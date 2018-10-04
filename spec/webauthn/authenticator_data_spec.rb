# frozen_string_literal: true

RSpec.describe WebAuthn::AuthenticatorData do
  let(:authenticator) do
    FakeAuthenticator::Base.new(rp_id: rp_id, sign_count: sign_count, context: { user_present: user_presence })
  end

  let(:rp_id) { "localhost" }
  let(:sign_count) { 42 }
  let(:user_presence) { true }

  let(:authenticator_data) { described_class.new(authenticator.authenticator_data) }

  describe "#rp_id_hash" do
    subject { authenticator_data.rp_id_hash }
    it { is_expected.to eq(authenticator.rp_id_hash) }
  end

  describe "#sign_count" do
    subject { authenticator_data.sign_count }
    it { is_expected.to eq(42) }
  end

  describe "#user_present?" do
    subject { authenticator_data.user_present? }
    context "when UP flag is set" do
      let(:user_presence) { true }
      it { is_expected.to be_truthy }
    end

    context "when UP flag is not set" do
      let(:user_presence) { false }
      it { is_expected.to be_falsy }
    end
  end
end
