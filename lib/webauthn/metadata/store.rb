# frozen_string_literal: true

require "webauthn/metadata/client"
require "webauthn/metadata/table_of_contents"

module WebAuthn
  module Metadata
    class Store
      METADATA_ENDPOINT = URI("https://mds2.fidoalliance.org/")

      def fetch_entry(aaguid: nil, attestation_certificate_key_id: nil)
        verify_arguments(aaguid: aaguid, attestation_certificate_key_id: attestation_certificate_key_id)

        if aaguid
          table_of_contents.entries.detect { |entry| entry.aaguid == aaguid }
        elsif attestation_certificate_key_id
          table_of_contents.entries.detect do |entry|
            entry.attestation_certificate_key_identifiers&.detect do |id|
              id == attestation_certificate_key_id
            end
          end
        end
      end

      def fetch_statement(aaguid: nil, attestation_certificate_key_id: nil)
        verify_arguments(aaguid: aaguid, attestation_certificate_key_id: attestation_certificate_key_id)

        key = "statement_#{aaguid || attestation_certificate_key_id}"
        statement = cache_backend.read(key)
        return statement if statement

        entry = if aaguid
                  fetch_entry(aaguid: aaguid)
                elsif attestation_certificate_key_id
                  fetch_entry(attestation_certificate_key_id: attestation_certificate_key_id)
                end
        return unless entry

        json = client.download_entry(entry.url, expected_hash: entry.hash)
        statement = WebAuthn::Metadata::Statement.from_json(json)
        cache_backend.write(key, statement)
        statement
      end

      private

      def verify_arguments(aaguid: nil, attestation_certificate_key_id: nil)
        unless aaguid || attestation_certificate_key_id
          raise ArgumentError, "must pass either aaguid or attestation_certificate_key"
        end

        if aaguid && attestation_certificate_key_id
          raise ArgumentError, "cannot pass both aaguid and attestation_certificate_key"
        end
      end

      def cache_backend
        WebAuthn.configuration.cache_backend || raise("no cache_backend configured")
      end

      def metadata_token
        WebAuthn.configuration.metadata_token || raise("no metadata_token configured")
      end

      def client
        @client ||= WebAuthn::Metadata::Client.new(metadata_token)
      end

      def table_of_contents
        @table_of_contents ||= begin
          key = "metadata_toc"
          toc = cache_backend.read(key)
          return toc if toc

          json = client.download_toc(METADATA_ENDPOINT)
          toc = WebAuthn::Metadata::TableOfContents.from_json(json)
          cache_backend.write(key, toc)
          toc
        end
      end
    end
  end
end
