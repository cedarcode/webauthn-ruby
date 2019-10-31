# frozen_string_literal: true

require "spec_helper"

require "json"
require "openssl"
require "webauthn/attestation_statement/fido_u2f"

RSpec.describe "FidoU2f attestation" do
  describe "#valid?" do
    let(:credential_public_key) { OpenSSL::PKey::EC.new("prime256v1").generate_key.public_key }
    let(:client_data_hash) { OpenSSL::Digest::SHA256.digest({}.to_json) }

    let(:authenticator_data_bytes) do
      WebAuthn::FakeAuthenticator::AuthenticatorData.new(
        rp_id_hash: OpenSSL::Digest::SHA256.digest("RP"),
        credential: { id: "0".b * 16, public_key: credential_public_key },
        aaguid: WebAuthn::AuthenticatorData::AttestedCredentialData::ZEROED_AAGUID
      ).serialize
    end

    let(:authenticator_data) { WebAuthn::AuthenticatorData.new(authenticator_data_bytes) }
    let(:to_be_signed) do
      "\x00" +
        authenticator_data.rp_id_hash +
        client_data_hash +
        authenticator_data.credential.id +
        credential_public_key.to_bn.to_s(2)
    end

    let(:attestation_key) { OpenSSL::PKey::EC.new("prime256v1").generate_key }
    let(:signature) { attestation_key.sign("SHA256", to_be_signed) }

    let(:attestation_certificate_version) { 2 }
    let(:attestation_certificate_subject) { "/C=UY/O=ACME/OU=Authenticator Attestation/CN=CN" }
    let(:attestation_certificate_basic_constraints) { "CA:FALSE" }
    let(:attestation_certificate_ski) { "0123456789abcdef0123456789abcdef01234567" }
    let(:attestation_certificate_extensions) do
      extension_factory = OpenSSL::X509::ExtensionFactory.new
      [
        extension_factory.create_extension("basicConstraints", attestation_certificate_basic_constraints, true),
        extension_factory.create_extension("subjectKeyIdentifier", attestation_certificate_ski, false),
      ]
    end
    let(:attestation_certificate_start_time) { Time.now }
    let(:attestation_certificate_end_time) { Time.now + 60 }
    let(:attestation_certificate) do
      certificate = OpenSSL::X509::Certificate.new
      certificate.version = attestation_certificate_version
      certificate.subject = OpenSSL::X509::Name.parse(attestation_certificate_subject)
      certificate.issuer = root_certificate.subject
      certificate.not_before = attestation_certificate_start_time
      certificate.not_after = attestation_certificate_end_time
      certificate.public_key = attestation_key
      certificate.extensions = attestation_certificate_extensions

      certificate.sign(root_key, OpenSSL::Digest::SHA256.new)

      certificate.to_der
    end

    let(:root_key) { OpenSSL::PKey::EC.new("prime256v1").generate_key }
    let(:root_certificate_start_time) { Time.now }
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

      root_certificate.extensions = [extension_factory.create_extension("basicConstraints", "CA:TRUE", true)]

      root_certificate.sign(root_key, OpenSSL::Digest::SHA256.new)

      root_certificate
    end

    let(:statement) do
      WebAuthn::AttestationStatement::FidoU2f.new(
        "sig" => signature,
        "x5c" => [attestation_certificate]
      )
    end

    let(:metadata_statement_root_certificates) { [root_certificate] }
    let(:metadata_attestation_certificate_key_ids) { [attestation_certificate_ski] }
    let(:metadata_statement) do
      statement = WebAuthn::Metadata::Statement.new
      statement.attestation_certificate_key_identifiers = metadata_attestation_certificate_key_ids
      statement.attestation_root_certificates = metadata_statement_root_certificates
      statement
    end
    let(:metadata_statement_key) { "statement_#{attestation_certificate_ski}" }
    let(:metadata_entry) do
      entry = WebAuthn::Metadata::Entry.new
      entry.attestation_certificate_key_identifiers = metadata_attestation_certificate_key_ids
      entry
    end
    let(:metadata_toc_entries) { [metadata_entry] }
    let(:metadata_toc) do
      toc = WebAuthn::Metadata::TableOfContents.new
      toc.entries = metadata_toc_entries
      toc
    end

    before do
      WebAuthn.configuration.cache_backend.write(metadata_statement_key, metadata_statement)
      WebAuthn.configuration.cache_backend.write("metadata_toc", metadata_toc)
    end

    it "works if everything's fine" do
      expect(statement.valid?(authenticator_data, client_data_hash)).to be_truthy
    end

    context "when signature is invalid" do
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

    context "when the attested credential public key is invalid" do
      context "because the coordinates are longer than expected" do
        let(:credential_public_key) do
          OpenSSL::PKey::EC.new("secp384r1").generate_key.public_key
        end

        it "fails" do
          expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
        end
      end
    end

    context "when the attestation certificate is invalid" do
      context "because there are too many" do
        let(:statement) do
          WebAuthn::AttestationStatement::FidoU2f.new(
            "sig" => signature,
            "x5c" => [attestation_certificate, attestation_certificate]
          )
        end

        it "fails" do
          expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
        end
      end

      context "because it is not of the correct type" do
        let(:attestation_key) { OpenSSL::PKey::RSA.new(2048) }

        it "fails" do
          expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
        end
      end

      context "because it is not of the correct curve" do
        let(:attestation_key) { OpenSSL::PKey::EC.new("secp384r1").generate_key }

        it "fails" do
          expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
        end
      end
    end

    context "when the AAGUID is invalid" do
      let(:authenticator_data_bytes) do
        WebAuthn::FakeAuthenticator::AuthenticatorData.new(
          rp_id_hash: OpenSSL::Digest::SHA256.digest("RP"),
          credential: { id: "0".b * 16, public_key: credential_public_key },
          aaguid: SecureRandom.random_bytes(16)
        ).serialize
      end

      it "fails" do
        expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
      end
    end

    context "when the metadata cannot verify the attestation statement" do
      context "because the attestation certificate key identifier is completely unknown" do
        let(:metadata_toc_entries) { [] }

        it "fails" do
          WebAuthn.configuration.cache_backend.delete(metadata_statement_key)

          expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
        end
      end
    end
  end
end
