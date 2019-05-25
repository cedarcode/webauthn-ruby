# frozen_string_literal: true

require "spec_helper"

require "cose/algorithm"
require "openssl"
require "webauthn/signature_verifier"

RSpec.describe "SignatureVerifier" do
  let(:signature) { key.sign(hash_algorithm, to_be_signed) }
  let(:to_be_signed) { "data" }
  let(:hash_algorithm) { COSE::Algorithm.find(algorithm_id).hash }
  let(:verifier) { WebAuthn::SignatureVerifier.new(algorithm_id, public_key) }

  context "ES256" do
    let(:algorithm_id) { -7 }

    let(:public_key) do
      pkey = OpenSSL::PKey::EC.new("prime256v1")
      pkey.public_key = key.public_key

      pkey
    end

    let(:key) { OpenSSL::PKey::EC.new("prime256v1").generate_key }

    it "works" do
      expect(verifier.verify(signature, to_be_signed)).to be_truthy
    end

    context "when it was signed using a different hash algorithm" do
      let(:hash_algorithm) { "SHA1" }

      it "fails" do
        expect(verifier.verify(signature, to_be_signed)).to be_falsy
      end
    end

    context "when it is valid but in an RSA context" do
      let(:public_key) { key.public_key }
      let(:key) { OpenSSL::PKey::RSA.new(2048) }

      it "fails" do
        expect { verifier.verify(signature, to_be_signed) }.to raise_error("Incompatible algorithm and key")
      end
    end

    context "when it was signed with a different key" do
      let(:signature) { OpenSSL::PKey::EC.new("prime256v1").generate_key.sign(hash_algorithm, to_be_signed) }

      it "fails" do
        expect(verifier.verify(signature, to_be_signed)).to be_falsy
      end
    end

    context "because it was signed over different data" do
      let(:signature) { key.sign(hash_algorithm, "different data") }

      it "fails" do
        expect(verifier.verify(signature, to_be_signed)).to be_falsy
      end
    end
  end

  context "PS256" do
    let(:signature) { key.sign_pss(hash_algorithm, to_be_signed, salt_length: :digest, mgf1_hash: hash_algorithm) }
    let(:algorithm_id) { -37 }
    let(:public_key) { key.public_key }
    let(:key) { OpenSSL::PKey::RSA.new(2048) }

    it "works" do
      expect(verifier.verify(signature, to_be_signed)).to be_truthy
    end

    context "when it was signed using a different hash algorithm" do
      let(:hash_algorithm) { "SHA1" }

      it "fails" do
        expect(verifier.verify(signature, to_be_signed)).to be_falsy
      end
    end

    context "when the masking generation function was using a different hash algorithm" do
      let(:signature) { key.sign_pss(hash_algorithm, to_be_signed, salt_length: :digest, mgf1_hash: "SHA1") }

      it "fails" do
        expect(verifier.verify(signature, to_be_signed)).to be_falsy
      end
    end

    context "when salt length is not equal to the hash function output" do
      let(:signature) { key.sign_pss(hash_algorithm, to_be_signed, salt_length: :max, mgf1_hash: hash_algorithm) }

      it "fails" do
        expect(verifier.verify(signature, to_be_signed)).to be_falsy
      end
    end

    context "when it is valid but in an EC context" do
      let(:public_key) do
        pkey = OpenSSL::PKey::EC.new("prime256v1")
        pkey.public_key = key.public_key

        pkey
      end

      let(:key) { OpenSSL::PKey::EC.new("prime256v1").generate_key }

      it "fails" do
        expect { verifier.verify(signature, to_be_signed) }.to raise_error("Incompatible algorithm and key")
      end
    end

    context "when it was signed with a different key" do
      let(:signature) do
        OpenSSL::PKey::RSA
          .new(2048)
          .sign_pss(hash_algorithm, to_be_signed, salt_length: :digest, mgf1_hash: hash_algorithm)
      end

      it "fails" do
        expect(verifier.verify(signature, to_be_signed)).to be_falsy
      end
    end

    context "when it was signed with the same key but using PKCS1-v1_5 padding" do
      let(:signature) { key.sign(hash_algorithm, to_be_signed) }

      it "fails" do
        expect(verifier.verify(signature, to_be_signed)).to be_falsy
      end
    end
  end

  context "RS256" do
    let(:algorithm_id) { -257 }
    let(:public_key) { key.public_key }
    let(:key) { OpenSSL::PKey::RSA.new(2048) }

    it "works" do
      expect(verifier.verify(signature, to_be_signed)).to be_truthy
    end

    context "when it was signed using a different hash algorithm" do
      let(:hash_algorithm) { "SHA1" }

      it "fails" do
        expect(verifier.verify(signature, to_be_signed)).to be_falsy
      end
    end

    context "when it is valid but in an EC context" do
      let(:public_key) do
        pkey = OpenSSL::PKey::EC.new("prime256v1")
        pkey.public_key = key.public_key

        pkey
      end

      let(:key) { OpenSSL::PKey::EC.new("prime256v1").generate_key }

      it "fails" do
        expect { verifier.verify(signature, to_be_signed) }.to raise_error("Incompatible algorithm and key")
      end
    end

    context "when it was signed with a different key" do
      let(:signature) { OpenSSL::PKey::RSA.new(2048).sign(hash_algorithm, to_be_signed) }

      it "fails" do
        expect(verifier.verify(signature, to_be_signed)).to be_falsy
      end
    end

    context "when it was signed with the same key but using PSS" do
      let(:signature) { key.sign_pss(hash_algorithm, to_be_signed, salt_length: :digest, mgf1_hash: hash_algorithm) }

      it "fails" do
        expect(verifier.verify(signature, to_be_signed)).to be_falsy
      end
    end
  end

  context "RS1" do
    let(:algorithm_id) { -65535 }
    let(:public_key) { key.public_key }
    let(:key) { OpenSSL::PKey::RSA.new(2048) }

    before do
      WebAuthn.configuration.algorithms << "RS1"
    end

    it "works" do
      expect(verifier.verify(signature, to_be_signed)).to be_truthy
    end

    context "when it was signed using a different hash algorithm" do
      let(:hash_algorithm) { "SHA512" }

      it "fails" do
        expect(verifier.verify(signature, to_be_signed)).to be_falsy
      end
    end

    context "when it is valid but in an EC context" do
      let(:public_key) do
        pkey = OpenSSL::PKey::EC.new("prime256v1")
        pkey.public_key = key.public_key

        pkey
      end

      let(:key) { OpenSSL::PKey::EC.new("prime256v1").generate_key }

      it "fails" do
        expect { verifier.verify(signature, to_be_signed) }.to raise_error("Incompatible algorithm and key")
      end
    end

    context "when it was signed with a different key" do
      let(:signature) { OpenSSL::PKey::RSA.new(2048).sign(hash_algorithm, to_be_signed) }

      it "fails" do
        expect(verifier.verify(signature, to_be_signed)).to be_falsy
      end
    end

    context "because it was signed over different data" do
      let(:signature) { key.sign(hash_algorithm, "different data") }

      it "fails" do
        expect(verifier.verify(signature, to_be_signed)).to be_falsy
      end
    end
  end

  context "when algorithm is unsupported" do
    let(:algorithm_id) { -260 }
    let(:hash_algorithm) { "SHA256" }

    let(:public_key) do
      pkey = OpenSSL::PKey::EC.new("prime256v1")
      pkey.public_key = key.public_key

      pkey
    end

    let(:key) { OpenSSL::PKey::EC.new("prime256v1").generate_key }

    it "fails" do
      expect {
        verifier.verify(signature, to_be_signed)
      }.to raise_error(WebAuthn::SignatureVerifier::UnsupportedAlgorithm, "Unsupported algorithm -260")
    end
  end
end
