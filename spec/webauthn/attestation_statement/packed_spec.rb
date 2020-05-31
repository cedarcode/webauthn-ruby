# frozen_string_literal: true

require "spec_helper"

require "json"
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

    let(:authenticator_data) { WebAuthn::AuthenticatorData.deserialize(authenticator_data_bytes) }
    let(:to_be_signed) { authenticator_data.data + client_data_hash }

    context "self attestation" do
      let(:algorithm) { -7 }
      let(:signature) { credential_key.sign("SHA256", to_be_signed) }
      let(:statement) { WebAuthn::AttestationStatement::Packed.new("alg" => algorithm, "sig" => signature) }

      it "works if everything's fine" do
        expect(statement.valid?(authenticator_data, client_data_hash)).to be_truthy
      end

      context "when RSA algorithm" do
        let(:algorithm) { -257 }
        let(:credential_key) { create_rsa_key }

        it "works" do
          expect(statement.valid?(authenticator_data, client_data_hash)).to be_truthy
        end
      end

      context "when credential public key algorithm doesn't match" do
        let(:credential_key) do
          WebAuthn.configuration.algorithms << "ES512"

          OpenSSL::PKey::EC.new("secp521r1").generate_key
        end

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
      let(:attestation_certificate_start_time) { Time.now - 1 }
      let(:attestation_certificate_end_time) { Time.now + 60 }

      let(:attestation_certificate) do
        certificate = OpenSSL::X509::Certificate.new
        certificate.version = attestation_certificate_version
        certificate.subject = OpenSSL::X509::Name.parse(attestation_certificate_subject)
        certificate.issuer = root_certificate.subject
        certificate.not_before = attestation_certificate_start_time
        certificate.not_after = attestation_certificate_end_time
        certificate.public_key = attestation_key

        extension_factory = OpenSSL::X509::ExtensionFactory.new
        extension_factory.subject_certificate = certificate
        extension_factory.issuer_certificate = certificate

        certificate.extensions = [
          extension_factory.create_extension("basicConstraints", attestation_certificate_basic_constraints, true),
        ]

        certificate.sign(root_key, OpenSSL::Digest::SHA256.new)

        certificate.to_der
      end

      let(:root_key) { OpenSSL::PKey::EC.new("prime256v1").generate_key }
      let(:root_certificate_start_time) { Time.now - 1 }
      let(:root_certificate_end_time) { Time.now + 60 }

      let(:root_certificate) do
        root_certificate = OpenSSL::X509::Certificate.new
        root_certificate.version = attestation_certificate_version
        root_certificate.subject = OpenSSL::X509::Name.parse("/DC=org/DC=fake-ca/CN=Fake CA")
        root_certificate.issuer = root_certificate.subject
        root_certificate.public_key = root_key
        root_certificate.not_before = root_certificate_start_time
        root_certificate.not_after = root_certificate_end_time

        extension_factory = OpenSSL::X509::ExtensionFactory.new
        extension_factory.subject_certificate = root_certificate
        extension_factory.issuer_certificate = root_certificate
        root_certificate.extensions = [
          extension_factory.create_extension("basicConstraints", "CA:TRUE", true),
          extension_factory.create_extension("keyUsage", "keyCertSign,cRLSign", true),
        ]

        root_certificate.sign(root_key, OpenSSL::Digest::SHA256.new)

        root_certificate
      end

      let(:statement) do
        WebAuthn::AttestationStatement::Packed.new(
          "alg" => algorithm,
          "sig" => signature,
          "x5c" => [attestation_certificate, root_certificate]
        )
      end

      before do
        WebAuthn.configuration.attestation_root_certificates_finders = finder_for(root_certificate)
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

        context "because it hasn't yet started" do
          let(:attestation_certificate_start_time) { Time.now + 10 }

          it "fails" do
            expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
          end
        end

        context "because it has expired" do
          let(:attestation_certificate_end_time) { Time.now - 1 }

          it "fails" do
            expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
          end
        end
      end

      context "when the certificate chain is invalid" do
        context "because a cert hasn't yet started" do
          let(:root_certificate_start_time) { Time.now + 10 }

          it "fails" do
            expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
          end
        end

        context "because a cert has expired" do
          let(:root_certificate_end_time) { Time.now - 1 }

          it "fails" do
            expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
          end
        end

        context "when finder doesn't have correct certificate" do
          before do
            WebAuthn.configuration.attestation_root_certificates_finders = finder_for(
              'incorrect_root.crt',
              return_empty: true
            )
          end

          it "fails" do
            expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
          end
        end
      end
    end
  end
end
