# frozen_string_literal: true

require "fido_metadata"
require "fido_metadata/test_cache_store"
require "zip"

class ConformanceCacheStore < FidoMetadata::TestCacheStore
  def setup_authenticators
    filename = "metadata.zip"
    puts("#{filename} not found, this will affect Metadata Service Test results.") unless File.exist?(filename)

    Zip::File.open(filename).glob("metadataStatements/*.json") do |file|
      json = JSON.parse(file.get_input_stream.read)
      statement = FidoMetadata::Statement.from_json(json)
      identifier = statement.aaguid || statement.attestation_certificate_key_identifiers.first
      write("statement_#{identifier}", statement)
    end
  end
end
