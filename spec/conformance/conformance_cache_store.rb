# frozen_string_literal: true

require "zip"
require_relative "../support/test_cache_store"

class ConformanceCacheStore < TestCacheStore
  def setup_authenticators
    filename = "metadata.zip"
    puts("#{filename} not found, this will affect Metadata Service Test results.") unless File.exist?(filename)

    Zip::File.open(filename).glob("metadataStatements/*.json") do |file|
      json = JSON.parse(file.get_input_stream.read)
      statement = WebAuthn::Metadata::Statement.from_json(json)
      write("statement_#{statement.aaguid}", statement)
    end
  end

  def setup_metadata_store
    puts("Setting up metadata store TOC")
    response = Net::HTTP.post(
      URI("https://fidoalliance.co.nz/mds/getEndpoints"),
      { endpoint: WebAuthn.configuration.origin }.to_json,
      WebAuthn::Metadata::Client::DEFAULT_HEADERS
    )
    response.value
    possible_endpoints = JSON.parse(response.body)["result"]

    client = WebAuthn::Metadata::Client.new(nil)
    json = possible_endpoints.each_with_index do |uri, index|
      begin
        puts("Trying endpoint #{index}: #{uri}")
        break client.download_toc(URI(uri), trust_store: conformance_trust_store)
      rescue WebAuthn::Metadata::Client::DataIntegrityError, JWT::VerificationError
        nil
      end
    end

    if json.is_a?(Hash) && json.keys == ["legalHeader", "no", "nextUpdate", "entries"]
      puts("TOC setup done!")
      toc = WebAuthn::Metadata::TableOfContents.from_json(json)
      write("metadata_toc", toc)
    else
      puts("Unable to setup TOC!")
    end
  end

  private

  def conformance_trust_store
    store = OpenSSL::X509::Store.new
    store.purpose = OpenSSL::X509::PURPOSE_ANY
    store.flags = OpenSSL::X509::V_FLAG_CRL_CHECK | OpenSSL::X509::V_FLAG_CRL_CHECK_ALL
    file = File.read(File.join(__dir__, "..", "support", "MDSROOT.crt"))
    store.add_cert(OpenSSL::X509::Certificate.new(file))
  end
end
