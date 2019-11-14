# frozen_string_literal: true

require "openssl"
require "webauthn/encoder"

module WebAuthn
  def self.configuration
    @configuration ||= Configuration.new
  end

  def self.configure
    yield(configuration)
  end

  class Configuration
    class RootStoreNotSupportedError < StandardError; end

    def self.if_pss_supported(algorithm)
      OpenSSL::PKey::RSA.instance_methods.include?(:verify_pss) ? algorithm : nil
    end

    DEFAULT_ALGORITHMS = ["ES256", if_pss_supported("PS256"), "RS256"].compact.freeze

    attr_accessor :algorithms
    attr_accessor :encoding
    attr_accessor :origin
    attr_accessor :rp_id
    attr_accessor :rp_name
    attr_accessor :verify_attestation_statement
    attr_accessor :credential_options_timeout
    attr_accessor :silent_authentication
    attr_accessor :acceptable_attestation_types
    attr_reader :acceptable_root_certificates

    def initialize
      @algorithms = DEFAULT_ALGORITHMS.dup
      @encoding = WebAuthn::Encoder::STANDARD_ENCODING
      @verify_attestation_statement = true
      @credential_options_timeout = 120000
      @silent_authentication = false
      @acceptable_attestation_types = [:None, :Self, :Basic]
    end

    # This is the user-data encoder.
    # Used to decode user input and to encode data provided to the user.
    def encoder
      @encoder ||= WebAuthn::Encoder.new(encoding)
    end

    def acceptable_root_certificates=(store)
      raise RootStoreNotSupportedError unless store.method(:find).arity == 2

      @acceptable_root_certificates = store
    end
  end
end
