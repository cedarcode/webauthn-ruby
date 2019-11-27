# frozen_string_literal: true

require 'base64'
require 'openssl'
require 'zip'

class FakeRootCertificatesStore
  def initialize
    metadata_filename = 'metadata.zip'
    puts("Please add the metadata file to #{__dir__}") unless File.exist?(metadata_filename)

    @root_certificates = {}
    Zip::File.open(metadata_filename).glob("metadataStatements/*.json") do |entry|
      statement = JSON.parse(entry.get_input_stream.read)
      attestation_root_certificates = statement['attestationRootCertificates']
      if attestation_root_certificates
        id = statement['aaguid'] || statement['attestationCertificateKeyIdentifiers'][0]
        @root_certificates[id] = []
        attestation_root_certificates.each do |cert|
          @root_certificates[id] << OpenSSL::X509::Certificate.new(Base64.decode64(cert))
        end
      end
    end
  end

  def find(_format, id)
    @root_certificates[id] || []
  end
end
