# frozen_string_literal: true

require "openssl"
require "webauthn/credential"
require "webauthn/encoder"
require "webauthn/error"

module WebAuthn
  class RootCertificateFinderNotSupportedError < Error; end

  class RelyingParty
    def self.if_pss_supported(algorithm)
      OpenSSL::PKey::RSA.instance_methods.include?(:verify_pss) ? algorithm : nil
    end

    DEFAULT_ALGORITHMS = ["ES256", "PS256", "RS256"].compact.freeze

    def initialize(
      algorithms: DEFAULT_ALGORITHMS.dup,
      encoding: WebAuthn::Encoder::STANDARD_ENCODING,
      origin: nil,
      id: nil,
      name: nil,
      verify_attestation_statement: true,
      credential_options_timeout: 120000,
      silent_authentication: false,
      acceptable_attestation_types: ['None', 'Self', 'Basic', 'AttCA', 'Basic_or_AttCA', 'AnonCA'],
      attestation_root_certificates_finders: [],
      legacy_u2f_appid: nil
    )
      @algorithms = algorithms
      @encoding = encoding
      @origin = origin
      @id = id
      @name = name
      @verify_attestation_statement = verify_attestation_statement
      @credential_options_timeout = credential_options_timeout
      @silent_authentication = silent_authentication
      @acceptable_attestation_types = acceptable_attestation_types
      @legacy_u2f_appid = legacy_u2f_appid
      self.attestation_root_certificates_finders = attestation_root_certificates_finders
    end

    attr_accessor :algorithms,
                  :encoding,
                  :origin,
                  :id,
                  :name,
                  :verify_attestation_statement,
                  :credential_options_timeout,
                  :silent_authentication,
                  :acceptable_attestation_types,
                  :legacy_u2f_appid

    attr_reader :attestation_root_certificates_finders

    # This is the user-data encoder.
    # Used to decode user input and to encode data provided to the user.
    def encoder
      @encoder ||= WebAuthn::Encoder.new(encoding)
    end

    def attestation_root_certificates_finders=(finders)
      if !finders.respond_to?(:each)
        finders = [finders]
      end

      finders.each do |finder|
        unless finder.respond_to?(:find)
          raise RootCertificateFinderNotSupportedError, "Finder must implement `find` method"
        end
      end

      @attestation_root_certificates_finders = finders
    end

    def options_for_registration(**keyword_arguments)
      WebAuthn::Credential.options_for_create(
        **keyword_arguments,
        relying_party: self
      )
    end

    def verify_registration(raw_credential, challenge, user_verification: nil)
      webauthn_credential = WebAuthn::Credential.from_create(raw_credential, relying_party: self)

      if webauthn_credential.verify(challenge, user_verification: user_verification)
        webauthn_credential
      end
    end

    def options_for_authentication(**keyword_arguments)
      WebAuthn::Credential.options_for_get(
        **keyword_arguments,
        relying_party: self
      )
    end

    def verify_authentication(
      raw_credential,
      challenge,
      user_verification: nil,
      public_key: nil,
      sign_count: nil
    )
      webauthn_credential = WebAuthn::Credential.from_get(raw_credential, relying_party: self)

      stored_credential = yield(webauthn_credential) if block_given?

      if webauthn_credential.verify(
        challenge,
        public_key: public_key || stored_credential.public_key,
        sign_count: sign_count || stored_credential.sign_count,
        user_verification: user_verification
      )
        block_given? ? [webauthn_credential, stored_credential] : webauthn_credential
      end
    end
  end
end
