# frozen_string_literal: true

require "spec_helper"

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
        aaguid: WebAuthn::AttestationStatement::FidoU2f::VALID_ATTESTED_AAGUID
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

    let(:attestation_certificate) do
      certificate = OpenSSL::X509::Certificate.new
      certificate.not_before = Time.now
      certificate.not_after = Time.now + 60
      certificate.public_key = attestation_key

      certificate.sign(attestation_key, OpenSSL::Digest::SHA256.new)

      certificate.to_der
    end

    let(:statement) do
      WebAuthn::AttestationStatement::FidoU2f.new(
        "sig" => signature,
        "x5c" => [attestation_certificate]
      )
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
  end
end
