# frozen_string_literal: true

require "spec_helper"

require "openssl"
require "webauthn/attestation_statement/tpm"

require "tpm/constants"
require "tpm/sized_buffer"
require "tpm/s_attest"
require "tpm/t_public"

RSpec.describe "TPM attestation statement" do
  describe "#valid?" do
    context "AttCA attestation" do
      let(:authenticator_data) { WebAuthn::AuthenticatorData.new(authenticator_data_bytes) }

      let(:authenticator_data_bytes) do
        WebAuthn::FakeAuthenticator::AuthenticatorData.new(
          rp_id_hash: OpenSSL::Digest::SHA256.digest("RP"),
          credential: { id: "0".b * 16, public_key: credential_key.public_key },
        ).serialize
      end

      let(:credential_key) { OpenSSL::PKey::RSA.new(credential_key_length) }
      let(:credential_key_length) { 2048 }
      let(:client_data_hash) { OpenSSL::Digest::SHA256.digest({}.to_json) }
      let(:algorithm) { -257 }

      let(:aik_certificate) do
        cert = OpenSSL::X509::Certificate.new
        cert.version = aik_certificate_version
        cert.subject = OpenSSL::X509::Name.parse(aik_certificate_subject)
        cert.not_before = aik_certificate_start_time
        cert.not_after = aik_certificate_end_time
        cert.public_key = aik

        extension_factory = OpenSSL::X509::ExtensionFactory.new

        cert.extensions = [
          extension_factory.create_extension("basicConstraints", aik_certificate_basic_constraints, true),
          extension_factory.create_extension("extendedKeyUsage", aik_certificate_extended_key_usage)
        ]

        cert.sign(aik, OpenSSL::Digest::SHA256.new)

        cert
      end

      let(:aik) { OpenSSL::PKey::RSA.new(2048) }
      let(:aik_certificate_version) { 2 }
      let(:aik_certificate_subject) { "" }
      let(:aik_certificate_basic_constraints) { "CA:FALSE" }
      let(:aik_certificate_extended_key_usage) { WebAuthn::AttestationStatement::TPM::OID_TCG_KP_AIK_CERTIFICATE }
      let(:aik_certificate_start_time) { Time.now }
      let(:aik_certificate_end_time) { Time.now + 60 }

      let(:signature) do
        aik.sign("SHA256", to_be_signed)
      end

      let(:to_be_signed) { cert_info }

      let(:cert_info) do
        s_attest = ::TPM::SAttest.new
        s_attest.magic = cert_info_magic
        s_attest.attested_type = ::TPM::ST_ATTEST_CERTIFY
        s_attest.extra_data.buffer = cert_info_extra_data
        s_attest.attested.name.buffer = cert_info_attested_name

        s_attest.to_binary_s
      end

      let(:cert_info_magic) { ::TPM::GENERATED_VALUE }
      let(:cert_info_extra_data) { OpenSSL::Digest::SHA256.digest(att_to_be_signed) }
      let(:cert_info_attested_name) { [::TPM::ALG_SHA256].pack("n") + OpenSSL::Digest::SHA256.digest(pub_area) }
      let(:att_to_be_signed) { authenticator_data_bytes + client_data_hash }

      let(:pub_area) do
        t_public = ::TPM::TPublic.new
        t_public.alg_type = ::TPM::ALG_RSA
        t_public.name_alg = ::TPM::ALG_SHA256
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

      it "works if everything's fine" do
        expect(statement.valid?(authenticator_data, client_data_hash)).to be_truthy
      end

      context "when EC algorithm" do
        let(:algorithm) { -7 }
        let(:aik) { OpenSSL::PKey::EC.new("prime256v1").generate_key }
        let(:credential_key) { OpenSSL::PKey::EC.new("prime256v1").generate_key }

        let(:pub_area) do
          t_public = ::TPM::TPublic.new
          t_public.alg_type = ::TPM::ALG_ECC
          t_public.name_alg = ::TPM::ALG_SHA256
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
              t_public.name_alg = ::TPM::ALG_SHA256
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

            context "because scheme doesn't match the statement alg" do
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
            t_public.name_alg = ::TPM::ALG_SHA256
            t_public.unique.buffer = OpenSSL::PKey::RSA.new(2048).params["n"].to_s(2)

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

          context "because scheme doesn't match the statement alg" do
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

      context "when certInfo is invalid" do
        context "because magic is not TPM_GENERATED_VALUE" do
          let(:cert_info_magic) { ::TPM::GENERATED_VALUE + 1 }

          it "returns false" do
            expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
          end
        end

        context "because extraData is the hash of attToBeSigned but not using the algorithm from 'alg'" do
          let(:cert_info_extra_data) { OpenSSL::Digest::SHA1.digest(att_to_be_signed) }

          it "returns false" do
            expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
          end
        end

        context "because attested name is not a valid Name for pubArea" do
          context "because it was hashed on different data" do
            let(:cert_info_attested_name) do
              [::TPM::ALG_SHA256].pack("n") + OpenSSL::Digest::SHA256.digest(pub_area + "X")
            end

            it "returns false" do
              expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
            end
          end

          context "because it was hashed with a different algorithm" do
            let(:cert_info_attested_name) do
              [::TPM::ALG_SHA1].pack("n") + OpenSSL::Digest::SHA1.digest(pub_area)
            end

            it "returns false" do
              expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
            end
          end
        end
      end

      context "when signature is invalid" do
        context "because is signed with a different alg" do
          let(:algorithm) { -258 }

          it "fails" do
            expect {
              statement.valid?(authenticator_data, client_data_hash)
            }.to raise_error("Unsupported algorithm -258")
          end
        end

        context "because it was signed with an incorrect key" do
          let(:signature) { OpenSSL::PKey::EC.new("prime256v1").generate_key.sign("SHA256", to_be_signed) }

          it "returns false" do
            expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
          end
        end

        context "because it was signed over different data" do
          let(:to_be_signed) { "other data".b }

          it "returns false" do
            expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
          end
        end

        context "because it is nonsense" do
          let(:signature) { "corrupted signature".b }

          it "returns false" do
            expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
          end
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
          let(:aik_certificate_end_time) { Time.now }

          it "returns false" do
            expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy
          end
        end
      end
    end

    context "ECDAA attestation" do
      let(:statement) do
        WebAuthn::AttestationStatement::TPM.new(
          "ver" => "2.0",
          "alg" => -260,
          "ecdaaKeyId" => "ecdaa-key-id",
          "sig" => "sig",
          "certInfo" => "cert-info",
          "pubArea" => "pub-area"
        )
      end

      it "tells the user it's not yet supported" do
        expect {
          statement.valid?("authenticator-data", "client-data-hash")
        }.to raise_error(
          WebAuthn::AttestationStatement::Base::NotSupportedError,
          "Attestation type ECDAA is not supported"
        )
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
