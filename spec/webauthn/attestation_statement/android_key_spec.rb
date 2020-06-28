# frozen_string_literal: true

require "spec_helper"

require "json"
require "openssl"
require "webauthn/attestation_statement/android_key"

RSpec.describe "AndroidKey attestation" do
  describe "#valid?" do
    let(:credential_key) { OpenSSL::PKey::EC.new("prime256v1").generate_key }
    let(:client_data_hash) { OpenSSL::Digest::SHA256.digest({}.to_json) }

    let(:authenticator_data_bytes) do
      WebAuthn::FakeAuthenticator::AuthenticatorData.new(
        rp_id_hash: OpenSSL::Digest.digest("SHA256", "RP"),
        credential: { id: "0".b * 16, public_key: credential_key.public_key },
      ).serialize
    end

    let(:authenticator_data) { WebAuthn::AuthenticatorData.deserialize(authenticator_data_bytes) }
    let(:to_be_signed) { authenticator_data.data + client_data_hash }

    let(:algorithm) { -7 }
    let(:attestation_key) { credential_key }
    let(:signature) { attestation_key.sign("SHA256", to_be_signed) }
    let(:attestation_certificate_attestation_challenge) { OpenSSL::ASN1::OctetString.new(client_data_hash) }
    let(:attestation_certificate_purpose) { OpenSSL::ASN1::Set.new([OpenSSL::ASN1::Integer.new(2)], 1, :EXPLICIT) }
    let(:attestation_certificate_origin) { OpenSSL::ASN1::Integer.new(0, 702, :EXPLICIT) }

    let(:attestation_certificate_tee_enforced) do
      OpenSSL::ASN1::Sequence.new([attestation_certificate_purpose, attestation_certificate_origin])
    end

    let(:attestation_certificate_software_enforced) { OpenSSL::ASN1::Sequence.new([]) }

    let(:attestation_certificate_extension) do
      OpenSSL::ASN1::Sequence.new(
        [
          OpenSSL::ASN1::Integer.new(3),
          OpenSSL::ASN1::Integer.new(0),
          OpenSSL::ASN1::Integer.new(0),
          OpenSSL::ASN1::Integer.new(0),
          attestation_certificate_attestation_challenge,
          OpenSSL::ASN1::OctetString.new(""),
          attestation_certificate_software_enforced,
          attestation_certificate_tee_enforced
        ]
      ).to_der
    end

    let(:attestation_certificate_extensions) do
      [OpenSSL::X509::Extension.new("1.3.6.1.4.1.11129.2.1.17", attestation_certificate_extension, false)]
    end

    let(:attestation_certificate) do
      certificate = OpenSSL::X509::Certificate.new
      certificate.subject = OpenSSL::X509::Name.new([["CN", "Fake Attestation"]])
      certificate.issuer = root_certificate.subject
      certificate.not_before = Time.now - 1
      certificate.not_after = Time.now + 60
      certificate.public_key = attestation_key

      extension_factory = OpenSSL::X509::ExtensionFactory.new
      extension_factory.subject_certificate = certificate
      extension_factory.issuer_certificate = certificate
      certificate.extensions = attestation_certificate_extensions

      certificate.sign(root_key, "SHA256")

      certificate.to_der
    end

    let(:statement) do
      WebAuthn::AttestationStatement::AndroidKey.new(
        "alg" => algorithm,
        "sig" => signature,
        "x5c" => [attestation_certificate]
      )
    end

    let(:root_key) { OpenSSL::PKey::EC.new("prime256v1").generate_key }
    let(:root_certificate) { create_root_certificate(root_key) }
    let(:google_certificates) { [root_certificate] }

    around do |example|
      silence_warnings do
        original_google_certificates = AndroidKeyAttestation::Statement::GOOGLE_ROOT_CERTIFICATES
        AndroidKeyAttestation::Statement::GOOGLE_ROOT_CERTIFICATES = google_certificates
        example.run
        AndroidKeyAttestation::Statement::GOOGLE_ROOT_CERTIFICATES = original_google_certificates
      end
    end

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

    context "when signature is invalid" do
      context "because is signed with a different alg" do
        let(:algorithm) { -36 }

        it "fails" do
          expect {
            statement.valid?(authenticator_data, client_data_hash)
          }.to raise_error("Unsupported algorithm -36")
        end
      end

      context "because it was signed with a different key" do
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

    context "when the attestation key doesn't match the credential key" do
      let(:attestation_key) { OpenSSL::PKey::EC.new("prime256v1").generate_key }

      it "fails" do
        expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
      end
    end

    context "when the attestation certificate doesn't meet requirements" do
      context "because attestationChallenge is invalid" do
        let(:attestation_certificate_attestation_challenge) { OpenSSL::ASN1::OctetString.new(client_data_hash[0..-2]) }

        it "fails" do
          expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
        end
      end

      context "because allApplications field is present teeEnforced" do
        let(:attestation_certificate_tee_enforced) do
          OpenSSL::ASN1::Sequence.new(
            [
              attestation_certificate_purpose,
              attestation_certificate_origin,
              OpenSSL::ASN1::Null.new(nil, 600, :EXPLICIT)
            ]
          )
        end

        it "fails" do
          expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
        end
      end

      context "because allApplications field is present softwareEnforced" do
        let(:attestation_certificate_software_enforced) do
          OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Null.new(nil, 600, :EXPLICIT)])
        end

        it "fails" do
          expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
        end
      end

      context "because AuthorizationList.purpose is invalid" do
        let(:attestation_certificate_purpose) { OpenSSL::ASN1::Set.new([OpenSSL::ASN1::Integer.new(3)], 1, :EXPLICIT) }

        it "fails" do
          expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
        end
      end

      context "because AuthorizationList.origin is invalid" do
        let(:attestation_certificate_origin) { OpenSSL::ASN1::Integer.new(1, 702, :EXPLICIT) }

        it "fails" do
          expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
        end
      end
    end

    context "when the attestation certificate is not signed by Google" do
      let(:google_certificates) do
        [create_root_certificate(OpenSSL::PKey::EC.new("prime256v1").generate_key)]
      end

      it "fails" do
        expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
      end

      it "returns true if they are configured" do
        WebAuthn.configuration.attestation_root_certificates_finders = finder_for(root_certificate)

        expect(statement.valid?(authenticator_data, client_data_hash)).to be_truthy
      end
    end
  end
end
