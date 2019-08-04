# frozen_string_literal: true

require "webauthn/metadata/client"
require "webauthn/metadata/table_of_contents"

module WebAuthn
  module Metadata
    class Store
      METADATA_ENDPOINT = URI("https://mds2.fidoalliance.org/")

      def fetch_entry(aaguid:)
        table_of_contents.entries.detect { |entry| entry.aaguid == aaguid }
      end

      def fetch_statement(aaguid:)
        key = "statement_#{aaguid}"
        statement = cache_backend.read(key)
        return statement if statement

        entry = fetch_entry(aaguid: aaguid)
        return unless entry

        json = client.download_entry(entry.url, expected_hash: entry.hash)
        statement = WebAuthn::Metadata::Statement.from_json(json)
        cache_backend.write(key, statement)
        statement
      end

      private

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
