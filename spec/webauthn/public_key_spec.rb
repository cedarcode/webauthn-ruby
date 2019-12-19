# frozen_string_literal: true

require "spec_helper"

require "webauthn/public_key"
require "support/seeds"
require "cose"
require "openssl"

RSpec.describe "PublicKey" do
  let(:uncompressed_point_public_key) do
    Base64.strict_decode64(seeds[:u2f_migration][:stored_credential][:public_key])
  end
  let(:cose_public_key) do
    Base64.urlsafe_decode64(
      "pQECAyYgASFYIPJKd_-Rl0QtQwbLggjGC_EbUFIMriCkdc2yuaukkBuNIlggaBsBjCwnMzFL7OUGJNm4b-HVpFNUa_NbsHGARuYKHfU"
    )
  end
  let(:webauthn_public_key) { WebAuthn::PublicKey.deserialize(public_key) }

  describe ".deserialize" do
    context "when invalid public key" do
      let(:public_key) { 'invalidinvalid' }

      it "should fail" do
        expect { webauthn_public_key }.to raise_error(COSE::MalformedKeyError)
      end
    end
  end

  describe "#pkey" do
    let(:pkey) { webauthn_public_key.pkey }

    context "when public key stored in uncompressed point format" do
      let(:public_key) { uncompressed_point_public_key }

      it "should return ssl pkey" do
        expect(pkey).to be_instance_of(OpenSSL::PKey::EC)
      end
    end

    context "when public key stored in cose format" do
      let(:public_key) { cose_public_key }

      it "should return ssl pkey" do
        expect(pkey).to be_instance_of(OpenSSL::PKey::EC)
      end
    end
  end

  describe "#cose_key" do
    let(:cose_key) { webauthn_public_key.cose_key }

    context "when public key stored in uncompressed point format" do
      let(:public_key) { uncompressed_point_public_key }

      it "should return EC2 cose key" do
        expect(cose_key).to be_instance_of(COSE::Key::EC2)
      end
    end

    context "when public key stored in cose format" do
      let(:public_key) { cose_public_key }

      it "should return cose key" do
        expect(cose_key).to be_a(COSE::Key::Base)
      end
    end
  end

  describe "#alg" do
    let(:alg) { webauthn_public_key.alg }

    context "when public key stored in uncompressed point format" do
      let(:public_key) { uncompressed_point_public_key }

      it "should return ES256 cose algorithm id" do
        expect(alg).to eq(COSE::Algorithm.by_name("ES256").id)
      end
    end

    context "when public key stored in cose format" do
      let(:public_key) { cose_public_key }

      it "should return cose algorithm id" do
        expect(alg).to be_a(Integer)
      end
    end
  end
end
