# frozen_string_literal: true

require "openssl"

module WebAuthn
  def self.configuration
    @configuration ||= Configuration.new
  end

  def self.configure
    yield(configuration)
  end

  class Configuration
    def self.if_pss_supported(algorithm)
      OpenSSL::PKey::RSA.instance_methods.include?(:verify_pss) ? algorithm : nil
    end

    DEFAULT_ALGORITHMS = ["ES256", if_pss_supported("PS256"), "RS256"].compact.freeze
    DEFAULT_ENCODING = :base64url

    attr_accessor :algorithms
    attr_accessor :encoding
    attr_accessor :origin
    attr_accessor :rp_id
    attr_accessor :rp_name
    attr_accessor :verify_attestation_statement
    attr_accessor :credential_options_timeout

    def initialize
      @algorithms = DEFAULT_ALGORITHMS.dup
      @encoding = DEFAULT_ENCODING
      @verify_attestation_statement = true
      @credential_options_timeout = 120000
    end
  end
end
