# frozen_string_literal: true

require "spec_helper"

require "openssl"
require "tpm/ek_certificate"

RSpec.describe "TPM::EKCertificate" do
  context "#conformant?" do
    let(:certificate) do
      certificate = OpenSSL::X509::Certificate.new
      certificate.version = certificate_version
      certificate.subject = OpenSSL::X509::Name.parse(certificate_subject)
      certificate.not_before = certificate_start_time
      certificate.not_after = certificate_end_time
      certificate.public_key = key

      extension_factory = OpenSSL::X509::ExtensionFactory.new
      extension_factory.config = certificate_san_config

      certificate.extensions = [
        extension_factory.create_extension("basicConstraints", certificate_basic_constraints, true),
        extension_factory.create_extension("extendedKeyUsage", certificate_extended_key_usage),
        extension_factory.create_extension("subjectAltName", "ASN1:SEQUENCE:dir_seq", certificate_san_critical),
      ]

      certificate.sign(key, OpenSSL::Digest::SHA256.new)

      certificate
    end

    let(:key) { OpenSSL::PKey::RSA.new(2048) }

    let(:certificate_version) { 2 }
    let(:certificate_subject) { "" }
    let(:certificate_start_time) { Time.now }
    let(:certificate_end_time) { certificate_start_time + 60 }
    let(:certificate_basic_constraints) { "CA:FALSE" }
    let(:certificate_extended_key_usage) { "2.23.133.8.3" }

    let(:certificate_san_critical) { true }
    let(:certificate_san_manufacturer) { "id:4E544300" }
    let(:certificate_san_model) { "TPM test model" }
    let(:certificate_san_version) { "id:42" }
    let(:certificate_san_config) do
      OpenSSL::Config.parse(<<~OPENSSL_CONF)
        [dir_seq]
        seq = EXPLICIT:4,SEQUENCE:dir_seq_seq

        [dir_seq_seq]
        set = SET:dir_set

        [dir_set]
        seq.1 = SEQUENCE:dir_seq_1
        seq.2 = SEQUENCE:dir_seq_2
        seq.3 = SEQUENCE:dir_seq_3

        [dir_seq_1]
        oid=OID:2.23.133.2.1
        str=UTF8:"#{certificate_san_manufacturer}"

        [dir_seq_2]
        oid=OID:2.23.133.2.2
        str=UTF8:"#{certificate_san_model}"

        [dir_seq_3]
        oid=OID:2.23.133.2.3
        str=UTF8:"#{certificate_san_version}"
      OPENSSL_CONF
    end

    let(:ek_certificate) { TPM::EKCertificate.new(certificate) }

    it "returns true if everything's in place" do
      expect(ek_certificate).to be_conformant
    end

    context "when version is incorrect" do
      let(:certificate_version) { 3 }

      it "returns false" do
        expect(ek_certificate).not_to be_conformant
      end
    end

    context "when Extended Key Usage extension is not tcg-kp-AIKCertificate OID" do
      let(:certificate_extended_key_usage) { "2.23.133.8.4" }

      it "returns false" do
        expect(ek_certificate).not_to be_conformant
      end
    end

    context "when Basic Constrains extension is not set to CA:FALSE" do
      let(:certificate_basic_constraints) { "CA:TRUE" }

      it "returns false" do
        expect(ek_certificate).not_to be_conformant
      end
    end

    context "when it hasn't yet started" do
      let(:certificate_start_time) { Time.now + 30 }

      it "returns false" do
        expect(ek_certificate).not_to be_conformant
      end
    end

    context "when it has expired" do
      let(:certificate_end_time) { Time.now }

      it "returns false" do
        expect(ek_certificate).not_to be_conformant
      end
    end

    context "when the subject alternative name is invalid" do
      context "because the extension is not critical when the subject is empty" do
        let(:certificate_san_critical) { false }
        let(:certificate_subject) { "" }

        it "returns false" do
          expect(ek_certificate).not_to be_conformant
        end
      end

      context "because the extension is critical when the subject is not empty" do
        let(:certificate_san_critical) { true }
        let(:certificate_subject) { "/CN=CN" }

        it "returns false" do
          expect(ek_certificate).not_to be_conformant
        end
      end

      context "because the manufacturer is unknown" do
        let(:certificate_san_manufacturer) { "id:F0000000" }

        it "returns false" do
          expect(ek_certificate).not_to be_conformant
        end
      end

      context "because the model is blank" do
        let(:certificate_san_model) { "" }

        it "returns false" do
          expect(ek_certificate).not_to be_conformant
        end
      end

      context "because the version is blank" do
        let(:certificate_san_version) { "" }

        it "returns false" do
          expect(ek_certificate).not_to be_conformant
        end
      end
    end
  end
end
