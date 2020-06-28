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
        rp_id_hash: OpenSSL::Digest.digest("SHA256", "RP"),
        credential: { id: "0".b * 16, public_key: credential_public_key },
        aaguid: WebAuthn::AuthenticatorData::AttestedCredentialData::ZEROED_AAGUID
      ).serialize
    end

    let(:authenticator_data) { WebAuthn::AuthenticatorData.deserialize(authenticator_data_bytes) }
    let(:to_be_signed) do
      "\x00" +
        authenticator_data.rp_id_hash +
        client_data_hash +
        authenticator_data.credential.id +
        credential_public_key.to_bn.to_s(2)
    end

    let(:attestation_key) { OpenSSL::PKey::EC.new("prime256v1").generate_key }
    let(:signature) { attestation_key.sign("SHA256", to_be_signed) }

    let(:attestation_certificate) do
      issue_certificate(root_certificate, root_key, attestation_key).to_der
    end

    let(:statement) do
      WebAuthn::AttestationStatement::FidoU2f.new(
        "sig" => signature,
        "x5c" => [attestation_certificate]
      )
    end

    let(:root_key) { OpenSSL::PKey::EC.new("prime256v1").generate_key }

    let(:root_certificate) do
      create_root_certificate(root_key)
    end

    before do
      WebAuthn.configuration.attestation_root_certificates_finders = finder_for(root_certificate)
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
          WebAuthn.configuration.algorithms << "ES384"

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
        let(:attestation_key) { create_rsa_key }

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
          rp_id_hash: OpenSSL::Digest.digest("SHA256", "RP"),
          credential: { id: "0".b * 16, public_key: credential_public_key },
          aaguid: SecureRandom.random_bytes(16)
        ).serialize
      end

      it "fails" do
        expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
      end
    end

    context "when the certificate chain is invalid" do
      context "when finder doesn't have correct certificate" do
        before do
          WebAuthn.configuration.attestation_root_certificates_finders = finder_for(
            nil,
            return_empty: true
          )
        end

        it "returns false" do
          expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
        end
      end
    end
  end
end
