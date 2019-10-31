# frozen_string_literal: true

require "spec_helper"
require "webauthn/metadata/store"

RSpec.describe WebAuthn::Metadata::Store do
  let(:aaguid) { "708fb93c-b8cf-48e1-81f4-e798a2c7627e" }
  let(:attestation_certificate_key_id) { "7c0903708b87115b0b422def3138c3c864e44573" }
  let(:entry) do
    entry = WebAuthn::Metadata::Entry.new
    entry.aaguid = aaguid
    entry
  end

  let(:toc_entries) { [entry] }
  let(:toc) do
    toc = WebAuthn::Metadata::TableOfContents.new
    toc.entries = toc_entries
    toc
  end

  let(:client) { instance_double(WebAuthn::Metadata::Client) }

  before do
    WebAuthn.configuration.cache_backend.write("metadata_toc", toc)
    WebAuthn.configuration.metadata_token = "foo"
    allow(WebAuthn::Metadata::Client).to receive(:new).and_return(client)
  end

  describe "configuration" do
    subject { described_class.new.fetch_statement(aaguid: aaguid) }

    it "raises with no store cache backend" do
      WebAuthn.configuration.cache_backend = nil

      expect { subject }.to raise_error(RuntimeError, "no cache_backend configured")
    end

    it "raises with no metadata service token" do
      WebAuthn.configuration.metadata_token = nil

      expect { subject }.to raise_error(RuntimeError, "no metadata_token configured")
    end
  end

  describe "#fetch_entry" do
    context "AAGUID" do
      subject { described_class.new.fetch_entry(aaguid: aaguid) }

      it "returns the metadata TOC entry if present" do
        expect(subject).to eq(entry)
      end

      context "if no entry can be found" do
        let(:toc_entries) { [] }

        it "returns nil" do
          expect(subject).to be_nil
        end
      end

      context "if no TOC is in the store backend" do
        before { WebAuthn.configuration.cache_backend.clear }

        it "downloads and returns the TOC" do
          expect(client).to receive(:download_toc).and_return("entries" => [{ "aaguid" => aaguid }])
          expect(subject.aaguid).to eq(aaguid)
        end
      end
    end

    context "attestation certificate key identifier" do
      let(:entry) do
        entry = WebAuthn::Metadata::Entry.new
        entry.attestation_certificate_key_identifiers = [attestation_certificate_key_id]
        entry
      end

      subject { described_class.new.fetch_entry(attestation_certificate_key_id: attestation_certificate_key_id) }

      it "returns the metadata TOC entry if present" do
        expect(subject).to eq(entry)
      end

      context "if no entry can be found" do
        let(:toc_entries) { [] }

        it "returns nil" do
          expect(subject).to be_nil
        end
      end

      context "if no TOC is in the store backend" do
        before { WebAuthn.configuration.cache_backend.clear }

        it "downloads and returns the TOC" do
          expect(client).to receive(:download_toc).and_return(
            "entries" => [{ "attestationCertificateKeyIdentifiers" => [attestation_certificate_key_id] }]
          )
          expect(subject.attestation_certificate_key_identifiers).to eq([attestation_certificate_key_id])
        end
      end
    end
  end

  describe "#fetch_statement" do
    context "AAGUID" do
      let(:statement) do
        statement = WebAuthn::Metadata::Statement.new
        statement.aaguid = aaguid
        statement
      end
      let(:statement_cache_key) { "statement_#{aaguid}" }

      before do
        WebAuthn.configuration.cache_backend.write(statement_cache_key, statement)
      end

      subject { described_class.new.fetch_statement(aaguid: aaguid) }

      context "the statement is present" do
        it "returns the statement" do
          expect(subject).to eq(statement)
        end
      end

      context "the statement is not present " do
        before { WebAuthn.configuration.cache_backend.delete(statement_cache_key) }

        context "the corresponding TOC entry is not present " do
          let(:toc_entries) { [] }

          it "returns nil" do
            expect(subject).to be_nil
          end
        end

        context "the corresponding TOC entry is present " do
          it "downloads and returns the statement" do
            expect(client).to receive(:download_entry).and_return("aaguid" => aaguid)
            expect(subject.aaguid).to eq(aaguid)
          end
        end
      end
    end

    context "attestation certificate key identifier" do
      let(:statement) do
        statement = WebAuthn::Metadata::Statement.new
        statement.attestation_certificate_key_identifiers = [attestation_certificate_key_id]
        statement
      end
      let(:statement_cache_key) { "statement_#{attestation_certificate_key_id}" }

      before do
        WebAuthn.configuration.cache_backend.write(statement_cache_key, statement)
      end

      subject { described_class.new.fetch_statement(attestation_certificate_key_id: attestation_certificate_key_id) }

      context "the statement is present" do
        it "returns the statement" do
          expect(subject).to eq(statement)
        end
      end

      context "the statement is not present" do
        before { WebAuthn.configuration.cache_backend.delete(statement_cache_key) }

        context "the corresponding TOC entry is not present " do
          let(:toc_entries) { [] }

          it "returns nil" do
            expect(subject).to be_nil
          end
        end

        context "the corresponding TOC entry is present" do
          let(:entry) do
            entry = WebAuthn::Metadata::Entry.new
            entry.attestation_certificate_key_identifiers = [attestation_certificate_key_id]
            entry
          end

          it "downloads and returns the statement" do
            expect(client).to receive(:download_entry).and_return(
              "attestationCertificateKeyIdentifiers" => [attestation_certificate_key_id]
            )
            expect(subject.attestation_certificate_key_identifiers).to match_array([attestation_certificate_key_id])
          end
        end
      end
    end
  end
end
