# frozen_string_literal: true

require "spec_helper"

require "json"
require "openssl"
require "webauthn/attestation_statement/tpm"

require "tpm/constants"
require "tpm/sized_buffer"
require "tpm/s_attest"
require "tpm/t_public"

RSpec.describe "TPM attestation statement" do
  describe "#valid?" do
    context "AttCA attestation" do
      let(:authenticator_data) { WebAuthn::AuthenticatorData.deserialize(authenticator_data_bytes) }

      let(:authenticator_data_bytes) do
        WebAuthn::FakeAuthenticator::AuthenticatorData.new(
          rp_id_hash: OpenSSL::Digest.digest("SHA256", "RP"),
          credential: { id: "0".b * 16, public_key: credential_key.public_key },
        ).serialize
      end

      let(:credential_key) { create_rsa_key }
      let(:credential_key_length) { credential_key.n.num_bits }
      let(:client_data_hash) { OpenSSL::Digest::SHA256.digest({}.to_json) }
      let(:algorithm) { -257 }

      let(:aik_certificate) do
        cert = OpenSSL::X509::Certificate.new
        cert.version = aik_certificate_version
        cert.issuer = root_certificate.subject
        cert.subject = OpenSSL::X509::Name.parse(aik_certificate_subject)
        cert.not_before = aik_certificate_start_time
        cert.not_after = aik_certificate_end_time
        cert.public_key = aik

        extension_factory = OpenSSL::X509::ExtensionFactory.new
        extension_factory.config = aik_certificate_san_config

        cert.extensions = [
          extension_factory.create_extension("basicConstraints", aik_certificate_basic_constraints, true),
          extension_factory.create_extension("extendedKeyUsage", aik_certificate_extended_key_usage),
          extension_factory.create_extension("subjectAltName", "ASN1:SEQUENCE:dir_seq", aik_certificate_san_critical),
        ]

        cert.sign(root_key, "SHA256")

        cert
      end

      let(:aik) { create_rsa_key }
      let(:aik_certificate_version) { 2 }
      let(:aik_certificate_subject) { "" }
      let(:aik_certificate_basic_constraints) { "CA:FALSE" }
      let(:aik_certificate_extended_key_usage) { ::TPM::AIKCertificate::OID_TCG_KP_AIK_CERTIFICATE }
      let(:aik_certificate_san_critical) { true }
      let(:aik_certificate_san_manufacturer) { "id:4E544300" }
      let(:aik_certificate_san_model) { "TPM test model" }
      let(:aik_certificate_san_version) { "id:42" }
      let(:aik_certificate_san_config) do
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
          str=UTF8:"#{aik_certificate_san_manufacturer}"

          [dir_seq_2]
          oid=OID:2.23.133.2.2
          str=UTF8:"#{aik_certificate_san_model}"

          [dir_seq_3]
          oid=OID:2.23.133.2.3
          str=UTF8:"#{aik_certificate_san_version}"
        OPENSSL_CONF
      end
      let(:aik_certificate_start_time) { Time.now - 1 }
      let(:aik_certificate_end_time) { Time.now + 60 }
      let(:root_key) { OpenSSL::PKey::RSA.new(2048) }
      let(:root_certificate) { create_root_certificate(root_key) }
      let(:signature) { aik.sign("SHA256", cert_info) }

      let(:cert_info) do
        s_attest = ::TPM::SAttest.new
        s_attest.magic = ::TPM::GENERATED_VALUE
        s_attest.attested_type = ::TPM::ST_ATTEST_CERTIFY
        s_attest.extra_data.buffer = cert_info_extra_data
        s_attest.attested.name.name.hash_alg = name_alg
        s_attest.attested.name.name.digest = OpenSSL::Digest::SHA1.digest(pub_area)

        s_attest.to_binary_s
      end

      let(:cert_info_extra_data) { OpenSSL::Digest::SHA256.digest(authenticator_data_bytes + client_data_hash) }
      let(:name_alg) { ::TPM::ALG_SHA1 }

      let(:pub_area) do
        t_public = ::TPM::TPublic.new
        t_public.alg_type = ::TPM::ALG_RSA
        t_public.name_alg = name_alg
        t_public.parameters = pub_area_parameters
        t_public.unique.buffer = credential_key.params["n"].to_s(2)

        t_public.to_binary_s
      end

      let(:pub_area_parameters) do
        {
          symmetric: ::TPM::ALG_NULL,
          scheme: ::TPM::ALG_RSASSA,
          key_bits: credential_key_length,
          exponent: 0x00
        }
      end

      let(:tpm_version) { "2.0" }

      let(:statement) do
        WebAuthn::AttestationStatement::TPM.new(
          "ver" => tpm_version,
          "alg" => algorithm,
          "x5c" => [aik_certificate.to_der],
          "sig" => signature,
          "certInfo" => cert_info,
          "pubArea" => pub_area
        )
      end

      let(:tpm_certificates) { [root_certificate] }

      around do |example|
        silence_warnings do
          original_tpm_certificates = ::TPM::KeyAttestation::ROOT_CERTIFICATES
          ::TPM::KeyAttestation::ROOT_CERTIFICATES = tpm_certificates
          example.run
          ::TPM::KeyAttestation::ROOT_CERTIFICATES = original_tpm_certificates
        end
      end

      it "works if everything's fine" do
        expect(statement.valid?(authenticator_data, client_data_hash)).to be_truthy
      end

      context "when the attestation certificate is not signed by a TPM" do
        let(:tpm_certificates) do
          [create_root_certificate(OpenSSL::PKey::RSA.new(2048))]
        end

        it "fails" do
          expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
        end

        it "returns true if they are configured" do
          WebAuthn.configuration.attestation_root_certificates_finders = finder_for(root_certificate)

          expect(statement.valid?(authenticator_data, client_data_hash)).to be_truthy
        end
      end

      context "when EC algorithm" do
        let(:algorithm) { -7 }
        let(:aik) { OpenSSL::PKey::EC.new("prime256v1").generate_key }
        let(:credential_key) { OpenSSL::PKey::EC.new("prime256v1").generate_key }

        let(:pub_area) do
          t_public = ::TPM::TPublic.new
          t_public.alg_type = ::TPM::ALG_ECC
          t_public.name_alg = name_alg
          t_public.parameters = pub_area_parameters
          t_public.unique.buffer = credential_key.public_key.to_bn.to_s(2)[1..-1]

          t_public.to_binary_s
        end

        let(:pub_area_parameters) do
          {
            symmetric: ::TPM::ALG_NULL,
            scheme: ::TPM::ALG_ECDSA,
            curve_id: ::TPM::ECC_NIST_P256,
            kdf: ::TPM::ALG_NULL
          }
        end

        it "works" do
          expect(statement.valid?(authenticator_data, client_data_hash)).to be_truthy
        end

        context "when pubArea is invalid" do
          context "because unique field doesn't represent the same key as credentialPublicKey" do
            let(:pub_area) do
              t_public = ::TPM::TPublic.new
              t_public.alg_type = ::TPM::ALG_ECC
              t_public.name_alg = name_alg
              t_public.parameters = pub_area_parameters
              t_public.unique.buffer =
                OpenSSL::PKey::EC.generate("prime256v1").generate_key.public_key.to_bn.to_s(2)[1..-1]

              t_public.to_binary_s
            end

            it "returns false" do
              expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
            end
          end

          context "because parameters are invalid" do
            context "because symmetric is not null" do
              let(:pub_area_parameters) do
                {
                  symmetric: ::TPM::ALG_NULL + 1,
                  scheme: ::TPM::ALG_ECDSA,
                  curve_id: ::TPM::ECC_NIST_P256,
                  kdf: ::TPM::ALG_NULL
                }
              end

              it "returns false" do
                expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
              end
            end

            context "because scheme doesn't match the credential key alg" do
              let(:pub_area_parameters) do
                {
                  symmetric: ::TPM::ALG_NULL,
                  scheme: ::TPM::ALG_ECDSA + 1,
                  curve_id: ::TPM::ECC_NIST_P256,
                  kdf: ::TPM::ALG_NULL
                }
              end

              it "returns false" do
                expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
              end
            end

            context "because curve id don't match the credential key curve" do
              let(:pub_area_parameters) do
                {
                  symmetric: ::TPM::ALG_NULL,
                  scheme: ::TPM::ALG_ECDSA,
                  curve_id: ::TPM::ECC_NIST_P256 + 1,
                  kdf: ::TPM::ALG_NULL
                }
              end

              it "returns false" do
                expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
              end
            end
          end
        end
      end

      context "when RSA PSS algorithm" do
        let(:algorithm) { -37 }
        let(:signature) do
          aik.sign_pss("SHA256", cert_info, salt_length: :max, mgf1_hash: "SHA256")
        end

        it "works if everything's fine" do
          expect(statement.valid?(authenticator_data, client_data_hash)).to be_truthy
        end
      end

      context "when TPM version is not 2.0" do
        let(:tpm_version) { "1.2" }

        it "returns false" do
          expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
        end
      end

      context "when pubArea is invalid" do
        context "because unique field doesn't represent the same key as credentialPublicKey" do
          let(:pub_area) do
            t_public = ::TPM::TPublic.new
            t_public.alg_type = ::TPM::ALG_RSA
            t_public.name_alg = name_alg
            t_public.unique.buffer = create_rsa_key.params["n"].to_s(2)

            t_public.to_binary_s
          end

          it "returns false" do
            expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
          end
        end

        context "because parameters are invalid" do
          context "because symmetric is not null" do
            let(:pub_area_parameters) do
              {
                symmetric: ::TPM::ALG_NULL + 1,
                scheme: ::TPM::ALG_RSASSA,
                key_bits: credential_key_length,
                exponent: 0x00
              }
            end

            it "returns false" do
              expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
            end
          end

          context "because scheme doesn't match the credential key alg" do
            let(:pub_area_parameters) do
              {
                symmetric: ::TPM::ALG_NULL,
                scheme: ::TPM::ALG_RSASSA + 1,
                key_bits: credential_key_length,
                exponent: 0x00
              }
            end

            it "returns false" do
              expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
            end
          end

          context "because key bits don't match the credential key length" do
            let(:pub_area_parameters) do
              {
                symmetric: ::TPM::ALG_NULL,
                scheme: ::TPM::ALG_RSASSA,
                key_bits: credential_key_length * 2,
                exponent: 0x00
              }
            end

            it "returns false" do
              expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
            end
          end
        end
      end

      context "when extraData is not the concatenation of auth data + client data hash" do
        let(:cert_info_extra_data) { OpenSSL::Digest::SHA256.digest(authenticator_data_bytes) }

        it "returns false" do
          expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
        end
      end

      context "when signature is invalid" do
        let(:signature) { "corrupted signature".b }

        it "returns false" do
          expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
        end
      end

      context "when the AIK certificate doesn't meet requirements" do
        context "because version is invalid" do
          let(:aik_certificate_version) { 1 }

          it "returns false" do
            expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
          end
        end

        context "because subject is not empty" do
          let(:aik_certificate_subject) { "/CN=CN" }

          it "returns false" do
            expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
          end
        end

        context "because Extended Key Usage extension is not tcg-kp-AIKCertificate OID" do
          let(:aik_certificate_extended_key_usage) { "2.23.133.8.4" }

          it "returns false" do
            expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
          end
        end

        context "because Basic Constrains extension is not set to CA:FALSE" do
          let(:aik_certificate_basic_constraints) { "CA:TRUE" }

          it "returns false" do
            expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
          end
        end

        context "because it hasn't yet started" do
          let(:aik_certificate_start_time) { Time.now + 10 }

          it "returns false" do
            expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
          end
        end

        context "because it has expired" do
          let(:aik_certificate_end_time) { Time.now - 1 }

          it "returns false" do
            expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
          end
        end

        context "when the subject alternative name is invalid" do
          context "because the extension is not critical" do
            let(:aik_certificate_san_critical) { false }

            it "returns false" do
              expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
            end
          end

          context "because the manufacturer is unknown" do
            let(:aik_certificate_san_manufacturer) { "id:F0000000" }

            it "returns false" do
              expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
            end
          end

          context "because the model is blank" do
            let(:aik_certificate_san_model) { "" }

            it "returns false" do
              expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
            end
          end

          context "because the version is blank" do
            let(:aik_certificate_san_version) { "" }

            it "returns false" do
              expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
            end
          end
        end
      end
    end

    context "when attestation type is not specified" do
      let(:statement) do
        WebAuthn::AttestationStatement::TPM.new(
          "ver" => "2.0",
          "alg" => -7,
          "sig" => "sig",
          "certInfo" => "cert-info",
          "pubArea" => "pub-area"
        )
      end

      it "fails" do
        expect {
          statement.valid?("authenticator-data", "client-data-hash")
        }.to raise_error("Attestation type invalid")
      end
    end
  end
end
