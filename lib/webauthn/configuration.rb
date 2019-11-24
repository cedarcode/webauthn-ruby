# frozen_string_literal: true

require "forwardable"
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
    extend Forwardable

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

    def_delegator :fido_metadata_configuration, :cache_backend, :fido_metadata_cache_backend
    def_delegator :fido_metadata_configuration, :cache_backend=, :fido_metadata_cache_backend=
    def_delegator :fido_metadata_configuration, :metadata_token, :fido_metadata_token
    def_delegator :fido_metadata_configuration, :metadata_token=, :fido_metadata_token=

    def initialize
      @algorithms = DEFAULT_ALGORITHMS.dup
      @encoding = WebAuthn::Encoder::STANDARD_ENCODING
      @verify_attestation_statement = true
      @credential_options_timeout = 120000
      @silent_authentication = false
    end

    # This is the user-data encoder.
    # Used to decode user input and to encode data provided to the user.
    def encoder
      @encoder ||= WebAuthn::Encoder.new(encoding)
    end

    private

    def fido_metadata_configuration
      FidoMetadata.configuration
    end
  end
end
