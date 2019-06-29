# frozen_string_literal: true

require "openssl/x509"

module WebAuthn
  module Metadata
    module Coercer
      module Certificates
        def self.coerce(values)
          return unless values.is_a?(Array)
          return values if values.all? { |value| value.is_a?(OpenSSL::X509::Certificate) }

          values.map { |value| OpenSSL::X509::Certificate.new(Base64.decode64(value)) }
        end
      end
    end
  end
end
