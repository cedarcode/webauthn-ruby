# frozen_string_literal: true

require "fido_metadata"
require "fido_metadata/test_cache_store"
require "zip"

class ConformanceCacheStore < FidoMetadata::TestCacheStore
  FILENAME = "metadata.zip"

  def setup_authenticators
    puts("#{FILENAME} not found, this will affect Metadata Service Test results.") unless File.exist?(FILENAME)

    Zip::File.open(FILENAME).glob("metadataStatements/*.json") do |file|
      json = JSON.parse(file.get_input_stream.read)
      statement = FidoMetadata::Statement.from_json(json)
      identifier = statement.aaguid || statement.attestation_certificate_key_identifiers.first
      write("statement_#{identifier}", statement)
    end
  end

  def setup_metadata_store(endpoint)
    puts("Setting up metadata store TOC")

    response = Net::HTTP.post(
      URI("https://mds3.fido.tools/getEndpoints"),
      { endpoint: endpoint }.to_json,
      FidoMetadata::Client::DEFAULT_HEADERS
    )

    response.value
    possible_endpoints = JSON.parse(response.body)["result"]

    client = FidoMetadata::Client.new

    json =
      possible_endpoints.each_with_index do |uri, index|
        puts("Trying endpoint #{index}: #{uri}")
        break client.download_toc(URI(uri), algorithms: ["ES256"], trusted_certs: conformance_certificates)
      rescue FidoMetadata::Client::DataIntegrityError, JWT::VerificationError, Net::HTTPFatalError
        nil
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
    file = File.read(File.join(__dir__, "MDSROOT.crt"))

    [OpenSSL::X509::Certificate.new(file)]
  end
end
