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
      write("statement_#{statement.aaguid}", statement)
    end
  end

  def setup_metadata_store
    puts("Setting up metadata store TOC")
    response = Net::HTTP.post(
      URI("https://fidoalliance.co.nz/mds/getEndpoints"),
      { endpoint: WebAuthn.configuration.origin }.to_json,
      FidoMetadata::Client::DEFAULT_HEADERS
    )
    response.value
    possible_endpoints = JSON.parse(response.body)["result"]

    client = FidoMetadata::Client.new(nil)
    json = possible_endpoints.each_with_index do |uri, index|
      begin
        puts("Trying endpoint #{index}: #{uri}")
        break client.download_toc(URI(uri), trusted_certs: conformance_certificates)
      rescue FidoMetadata::Client::DataIntegrityError, JWT::VerificationError, Net::HTTPFatalError
        nil
      end
    end

    if json.is_a?(Hash) && json.keys == ["legalHeader", "no", "nextUpdate", "entries"]
      puts("TOC setup done!")
      toc = FidoMetadata::TableOfContents.from_json(json)
      write("metadata_toc", toc)
    else
      puts("Unable to setup TOC!")
    end
  end

  private

  def conformance_certificates
    file = File.read(File.join(__dir__, "..", "support", "MDSROOT.crt"))
    [OpenSSL::X509::Certificate.new(file)]
  end
end
