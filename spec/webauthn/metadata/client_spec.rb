# frozen_string_literal: true

require "spec_helper"
require "webauthn/metadata/client"

RSpec.describe WebAuthn::Metadata::Client do
  let(:fake_token) { "6d6b44d78b09fed0c5559e34c71db291d0d322d4d4de0000" }
  let(:uri) { URI("https://fidoalliance.co.nz/mds/") }
  let(:response) { { status: 200, body: "" } }
  let(:support_path) { Pathname.new(File.expand_path(File.join(__dir__, "..", "..", "support"))) }
  let(:current_time) { Time.utc(2019, 5, 12) }

  before(:each) do
    stub_request(:get, uri).with(query: { "token" => fake_token }).to_return(response)
    allow(Time).to receive(:now).and_return(current_time)
  end

  context "#download_toc" do
    let(:toc) { File.read(support_path.join("mds_toc.txt")) }
    let(:response) { { status: 200, body: toc } }
    let(:trust_store) do
      store = OpenSSL::X509::Store.new
      store.purpose = OpenSSL::X509::PURPOSE_ANY
      store.flags = OpenSSL::X509::V_FLAG_CRL_CHECK | OpenSSL::X509::V_FLAG_CRL_CHECK_ALL
      file = File.read(support_path.join("MDSROOT.crt"))
      store.add_cert(OpenSSL::X509::Certificate.new(file))
      store.time = current_time.to_i
      store
    end
    let(:mdcsa_crl) { { status: 200, body: File.read(support_path.join("MDSCA-1.crl")) } }
    let(:mdsroot_crl) { { status: 200, body: File.read(support_path.join("MDSROOT.crl")) } }

    before(:each) do
      stub_request(:get, "https://fidoalliance.co.nz/mds/crl/MDSCA-1.crl").to_return(mdcsa_crl)
      stub_request(:get, "https://fidoalliance.co.nz/mds/crl/MDSROOT.crl").to_return(mdsroot_crl)
      stub_request(
        :get,
        "https://fidoalliance.co.nz/safetynetpki/crl/FIDO%20Fake%20Root%20Certificate%20Authority%202018.crl"
      ).to_return(status: 404)
    end

    subject { described_class.new(fake_token).download_toc(uri, trust_store: trust_store) }

    context "when everything's in place" do
      it "returns a MetadataTOCPayload hash with the required keys" do
        expect(subject).to include("nextUpdate", "entries", "no")
      end

      it "has MetadataTOCPayloadEntry objects" do
        expect(subject["entries"]).not_to be_empty
      end
    end

    context "when the x5c certificates are not trusted" do
      context "because the chain cannot be verified" do
        let(:toc) { File.read(support_path.join("mds_toc_invalid_chain.txt")) }

        specify do
          expect { subject }.to raise_error(
            described_class::UnverifiedSigningKeyError, "OpenSSL error 20 (unable to get local issuer certificate)"
          )
        end
      end

      context "because the certificate was revoked" do
        let(:toc) { File.read(support_path.join("mds_toc_revoked.txt")) }

        specify do
          expect { subject }.to raise_error(
            described_class::UnverifiedSigningKeyError, "OpenSSL error 23 (certificate revoked)"
          )
        end
      end
    end

    context "when the server responds with HTTP 500" do
      let(:response) { { status: 500, body: "test server error" } }

      specify do
        expect { subject }.to raise_error(Net::HTTPFatalError)
      end
    end

    context "when the server times out" do
      specify do
        stub_request(:get, uri).with(query: { "token" => fake_token }).to_timeout

        expect { subject }.to raise_error(Net::OpenTimeout)
      end
    end

    context "when the server responds with malformed JWT" do
      let(:response) { { status: 200, body: "aaa.bbb" } }

      specify do
        expect { subject }.to raise_error(JWT::DecodeError)
      end
    end

    context "when a CRL cannot be downloaded" do
      let(:mdcsa_crl) { { status: 404 } }

      specify do
        expect { subject }.to raise_error(
          described_class::UnverifiedSigningKeyError, "OpenSSL error 3 (unable to get certificate CRL)"
        )
      end
    end

    context "when a CRL is malformed" do
      let(:mdcsa_crl) { { status: 200, body: "crl" } }

      specify do
        expect { subject }.to raise_error(OpenSSL::X509::CRLError)
      end
    end

    context "when a CRL is expired" do
      let(:current_time) { Time.utc(2049, 1, 1) }

      specify do
        expect { subject }.to raise_error(
          described_class::UnverifiedSigningKeyError, "OpenSSL error 12 (CRL has expired)"
        )
      end
    end
  end

  context "#download_entry" do
    let(:entry) { File.read(support_path.join("mds_entry.txt")) }
    let(:response) { { status: 200, body: entry } }
    let(:uri) { URI("https://fidoalliance.co.nz/mds/metadata/cae4a9e5-4373-40d1-8826-9c3ddc817259.json/") }
    let(:hash) { "DtuJ-Cj8vlhqpQLk3VxDqPh8_uOUxfEiCGFGNpsQE6k" }

    subject { described_class.new(fake_token).download_entry(uri, expected_hash: hash) }

    context "when everything's in place" do
      it "returns a MetadataStatement hash with the required keys" do
        expect(subject).to include(
          "description", "authenticatorVersion", "upv", "assertionScheme",
          "authenticationAlgorithm", "publicKeyAlgAndEncoding", "attestationTypes", "userVerificationDetails",
          "keyProtection", "matcherProtection", "attachmentHint", "isSecondFactorOnly", "tcDisplay",
          "attestationRootCertificates"
        )
      end
    end

    context "when the server responds with HTTP 500" do
      let(:response) { { status: 500, body: "test server error" } }

      specify do
        expect { subject }.to raise_error(Net::HTTPFatalError)
      end
    end

    context "when the server times out" do
      specify do
        stub_request(:get, uri).with(query: { "token" => fake_token }).to_timeout

        expect { subject }.to raise_error(Net::OpenTimeout)
      end
    end

    context "when the actual hash does not match the expected hash" do
      let(:hash) { "LCa0a2j_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564" }

      specify do
        expect { subject }.to raise_error(described_class::InvalidHashError)
      end
    end

    context "when the urlsafe base64 JSON is malformed" do
      let(:entry) { File.read(support_path.join("mds_entry.txt"))[0..-10] }
      let(:response) { { status: 200, body: entry } }
      let(:hash) { Base64.urlsafe_encode64(OpenSSL::Digest::SHA256.digest(entry), padding: false) }

      specify do
        expect { subject }.to raise_error(JSON::ParserError)
      end
    end
  end
end
