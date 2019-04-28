# frozen_string_literal: true

require "spec_helper"
require "webauthn/metadata/client"

RSpec.describe WebAuthn::Metadata::Client do
  let(:fake_token) { "6d6b44d78b09fed0c5559e34c71db291d0d322d4d4de0000" }
  let(:uri) { URI("https://fidoalliance.co.nz/mds/") }
  let(:response) { { status: 200, body: "webmock response" } }
  let(:support_path) { Pathname.new(File.expand_path(File.join(__dir__, "..", "..", "support"))) }

  before(:each) do
    stub_request(:get, uri).with(query: { "token" => fake_token }).to_return(response)
  end

  context "#download_toc" do
    let(:toc) { File.read(support_path.join("toc.txt")) }
    let(:response) { { status: 200, body: toc } }
    let(:trust_store) do
      store = OpenSSL::X509::Store.new
      file = File.read(support_path.join("MDSROOT.crt"))
      store.add_cert(OpenSSL::X509::Certificate.new(file))
      store.time = Time.utc(2019, 4, 28).to_i
      store
    end

    subject { described_class.new(fake_token).download_toc(uri, trust_store: trust_store) }

    context "when everything's in place" do
      it "returns a MetadataTOCPayload with the required keys" do
        expect(subject).to include("nextUpdate", "entries", "no")
      end

      it "has MetadataTOCPayloadEntry objects" do
        expect(subject["entries"]).not_to be_empty
      end
    end

    context "when the x5c certificates are not trusted" do
      context "because the chain cannot be verified" do
        let(:trust_store) { OpenSSL::X509::Store.new }

        specify do
          expect { subject }.to raise_error(
            described_class::UnverifiedSigningKeyError, "OpenSSL error 20 (unable to get local issuer certificate)"
          )
        end
      end

      context "because a certificate has expired" do
        specify do
          trust_store.time = Time.utc(3000, 1, 1).to_i

          expect { subject }.to raise_error(
            described_class::UnverifiedSigningKeyError, "OpenSSL error 10 (certificate has expired)"
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
  end

  context "#download_entry" do
    let(:entry) { File.read(support_path.join("entry.txt")) }
    let(:response) { { status: 200, body: entry } }
    let(:uri) { URI("https://fidoalliance.co.nz/mds/metadata/cae4a9e5-4373-40d1-8826-9c3ddc817259.json/") }
    let(:hash) { "DtuJ-Cj8vlhqpQLk3VxDqPh8_uOUxfEiCGFGNpsQE6k" }

    subject { described_class.new(fake_token).download_entry(uri, expected_hash: hash) }

    context "when everything's in place" do
      it "returns a MetadataStatement with the required keys" do
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
      let(:entry) { File.read(support_path.join("entry.txt"))[0..-10] }
      let(:response) { { status: 200, body: entry } }
      let(:hash) { Base64.urlsafe_encode64(OpenSSL::Digest::SHA256.digest(entry), padding: false) }

      specify do
        expect { subject }.to raise_error(JSON::ParserError)
      end
    end
  end
end
