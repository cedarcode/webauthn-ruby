# frozen_string_literal: true

module WebAuthn
  class FakeRootCertificatesStore
    def find(_format, id)
      path = File.expand_path(File.join(__dir__, '..', 'support', 'fake_roots'))
      certificates = []
      Dir.glob("#{path}/#{id}*.pem") do |filename|
        certificates << OpenSSL::X509::Certificate.new(File.open(filename))
      end

      certificates
    end
  end
end
