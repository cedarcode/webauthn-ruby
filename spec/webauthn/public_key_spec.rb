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

  describe "#verify" do
    context "when public key stored in uncompressed point format" do
      let(:public_key) { uncompressed_point_public_key }

      context "when signature was signed with public key" do
        let(:signature) do
          Base64.strict_decode64(seeds[:u2f_migration][:assertion][:response][:signature])
        end
        let(:authenticator_data) do
          Base64.strict_decode64(seeds[:u2f_migration][:assertion][:response][:authenticator_data])
        end
        let(:client_data_hash) do
          WebAuthn::ClientData.new(
            Base64.strict_decode64(seeds[:u2f_migration][:assertion][:response][:client_data_json])
          ).hash
        end
        let(:verification_data) { authenticator_data + client_data_hash }

        it "should verify" do
          expect(
            webauthn_public_key.verify(signature, verification_data)
          ).to be_truthy
        end
      end
    end

    context "when public key stored in cose format" do
      let(:signature) { key.sign(hash_algorithm, to_be_signed) }
      let(:to_be_signed) { "data" }
      let(:hash_algorithm) do
        COSE::Algorithm.find("ES256").hash_function
      end
      let(:cose_key) do
        cose_key = COSE::Key::EC2.from_pkey(key.public_key)
        cose_key.alg = -7

        cose_key
      end
      let(:key) { OpenSSL::PKey::EC.generate("prime256v1") }
      let(:webauthn_public_key) { WebAuthn::PublicKey.new(cose_key: cose_key) }

      it "works" do
        expect(webauthn_public_key.verify(signature, to_be_signed)).to be_truthy
      end

      context "when it was signed using a different hash algorithm" do
        let(:hash_algorithm) { "SHA1" }

        it "fails" do
          expect(webauthn_public_key.verify(signature, to_be_signed)).to be_falsy
        end
      end

      context "when it was signed with a different key" do
        let(:signature) do
          OpenSSL::PKey::EC.generate("prime256v1").sign(
            hash_algorithm,
            to_be_signed
          )
        end

        it "fails" do
          expect(webauthn_public_key.verify(signature, to_be_signed)).to be_falsy
        end
      end

      context "when it was signed over different data" do
        let(:signature) { key.sign(hash_algorithm, "different data") }

        it "fails" do
          expect(webauthn_public_key.verify(signature, to_be_signed)).to be_falsy
        end
      end

      context "when public key algorithm is not in COSE" do
        let(:cose_key) do
          cose_key = COSE::Key::EC2.from_pkey(key.public_key)
          cose_key.alg = -1

          cose_key
        end

        it "fails" do
          expect { webauthn_public_key.verify(signature, to_be_signed) }.to(
            raise_error(
              WebAuthn::PublicKey::UnsupportedAlgorithm,
              "The public key algorithm -1 is not among the available COSE algorithms"
            )
          )
        end
      end
    end
  end
end
