# frozen_string_literal: true

module WebAuthn
  class FakeRootCertificatesStore
    ROOT_CERTIFICATES =
      begin
        path = File.expand_path(File.join(__dir__, '..', 'support', 'fake_roots'))
        certificates = []
        Dir.glob("#{path}/*.pem") do |filename|
          certificates << OpenSSL::X509::Certificate.new(File.open(filename))
        end

        certificates
      end

    def find(_format, _id)
      ROOT_CERTIFICATES
    end
  end
end
