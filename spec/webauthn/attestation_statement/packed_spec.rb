# frozen_string_literal: true

require "spec_helper"

require "openssl"
require "webauthn/attestation_statement/packed"

RSpec.describe "Packed attestation" do
  describe "#valid?" do
    let(:credential_key) { OpenSSL::PKey::EC.new("prime256v1").generate_key }
    let(:client_data_hash) { OpenSSL::Digest::SHA256.digest({}.to_json) }

    let(:authenticator_data_bytes) do
      WebAuthn::FakeAuthenticator::AuthenticatorData.new(
        rp_id_hash: OpenSSL::Digest::SHA256.digest("RP"),
        credential: { id: "0".b * 16, public_key: credential_key.public_key },
      ).serialize
    end

    let(:authenticator_data) { WebAuthn::AuthenticatorData.new(authenticator_data_bytes) }
    let(:to_be_signed) { authenticator_data.data + client_data_hash }

    context "self attestation" do
      let(:algorithm) { -7 }
      let(:signature) { credential_key.sign("SHA256", to_be_signed) }
      let(:statement) { WebAuthn::AttestationStatement::Packed.new("alg" => algorithm, "sig" => signature) }

      it "works if everything's fine" do
        expect(statement.valid?(authenticator_data, client_data_hash)).to be_truthy
      end

      context "when credential public key algorithm doesn't match" do
        let(:credential_key) { OpenSSL::PKey::EC.new("secp521r1").generate_key }

        it "fails" do
          expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
        end
      end

      context "when signature is invalid" do
        context "because is signed with a different alg" do
          let(:algorithm) { -36 }

          it "fails" do
            expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
          end
        end

        context "because it was signed with a different signing key" do
          let(:signature) { OpenSSL::PKey::EC.new("prime256v1").generate_key.sign("SHA256", to_be_signed) }

          it "fails" do
            expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
          end
        end

        context "because it was signed over different data" do
          let(:to_be_signed) { "other data" }

          it "fails" do
            expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
          end
        end

        context "because it is corrupted" do
          let(:signature) { "corrupted signature".b }

          it "fails" do
            expect { statement.valid?(authenticator_data, client_data_hash) }.to raise_error(OpenSSL::PKey::PKeyError)
          end
        end
      end
    end

    context "x5c attestation" do
      let(:algorithm) { -7 }
      let(:attestation_key) { OpenSSL::PKey::EC.new("prime256v1").generate_key }
      let(:signature) { attestation_key.sign("SHA256", to_be_signed) }
      let(:attestation_certificate_version) { 2 }
      let(:attestation_certificate_subject) { "/C=UY/O=ACME/OU=Authenticator Attestation/CN=CN" }
      let(:attestation_certificate_basic_constraints) { "CA:FALSE" }
      let(:attestation_certificate_aaguid) { authenticator_data.attested_credential_data.aaguid }

      let(:attestation_certificate) do
        certificate = OpenSSL::X509::Certificate.new
        certificate.version = attestation_certificate_version
        certificate.subject = OpenSSL::X509::Name.parse(attestation_certificate_subject)
        certificate.not_before = Time.now
        certificate.not_after = Time.now + 60
        certificate.public_key = attestation_key

        extension_factory = OpenSSL::X509::ExtensionFactory.new
        extension_factory.subject_certificate = certificate
        extension_factory.issuer_certificate = certificate

        certificate.extensions = [
          extension_factory.create_extension("basicConstraints", attestation_certificate_basic_constraints, true),
        ]

        certificate.sign(attestation_key, OpenSSL::Digest::SHA256.new)

        certificate.to_der
      end

      let(:statement) do
        WebAuthn::AttestationStatement::Packed.new(
          "alg" => algorithm,
          "sig" => signature,
          "x5c" => [attestation_certificate]
        )
      end

      it "works if everything's fine" do
        expect(statement.valid?(authenticator_data, client_data_hash)).to be_truthy
      end

      context "when signature is invalid" do
        context "because is signed with a different alg" do
          let(:algorithm) { -36 }

          it "fails" do
            expect {
              statement.valid?(authenticator_data, client_data_hash)
            }.to raise_error("Unsupported algorithm -36")
          end
        end

        context "because it was signed with a different signing key (self attested)" do
          let(:signature) { OpenSSL::PKey::EC.new("prime256v1").generate_key.sign("SHA256", to_be_signed) }

          it "fails" do
            expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
          end
        end

        context "because it was signed over different data" do
          let(:to_be_signed) { "other data" }

          it "fails" do
            expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
          end
        end

        context "because it is corrupted" do
          let(:signature) { "corrupted signature".b }

          it "fails" do
            expect { statement.valid?(authenticator_data, client_data_hash) }.to raise_error(OpenSSL::PKey::PKeyError)
          end
        end
      end

      context "when the attestation certificate doesn't meet requirements" do
        context "because version is invalid" do
          let(:attestation_certificate_version) { 1 }

          it "fails" do
            expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
          end
        end

        context "because subject is invalid" do
          let(:attestation_certificate_subject) { "/C=UY/O=ACME/OU=Incorrect/CN=CN" }

          it "fails" do
            expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
          end
        end

        context "because Basic Constrains extension is invalid" do
          let(:attestation_certificate_basic_constraints) { "CA:TRUE" }

          it "fails" do
            expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
          end
        end
      end
    end

    context "ECDAA" do
      let(:statement) do
        WebAuthn::AttestationStatement::Packed.new("alg" => -260, "sig" => "signature".b, "ecdaaKeyId" => "key-id".b)
      end

      it "tells the user it's not yet supported" do
        expect {
          statement.valid?(authenticator_data, client_data_hash)
        }.to raise_error(
          WebAuthn::AttestationStatement::Base::NotSupportedError,
          "ecdaaKeyId of the packed attestation format is not implemented yet"
        )
      end
    end
  end
end
