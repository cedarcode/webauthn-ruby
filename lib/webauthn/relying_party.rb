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

    DEFAULT_ALGORITHMS = ["ES256", if_pss_supported("PS256"), "RS256"].compact.freeze

    def initialize(
      algorithms: DEFAULT_ALGORITHMS.dup,
      encoding: WebAuthn::Encoder::STANDARD_ENCODING,
      origin: nil,
      id: nil,
      name: nil,
      verify_attestation_statement: true,
      credential_options_timeout: 120000,
      silent_authentication: false,
      acceptable_attestation_types: ['None', 'Self', 'Basic', 'AttCA', 'Basic_or_AttCA'],
      attestation_root_certificates_finders: []
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
      @attestation_root_certificates_finders = attestation_root_certificates_finders
    end

    attr_accessor :algorithms, :encoding, :origin, :id, :name,
                  :verify_attestation_statement, :credential_options_timeout,
                  :silent_authentication, :acceptable_attestation_types

    attr_reader :attestation_root_certificates_finders

    alias rp_name  name
    alias rp_name= name=
    alias rp_id    id
    alias rp_id=   id=

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

    def options_for_registration(params, user:, exclude:)
      WebAuthn::Credential.options_for_create(
        attestation: params["attestation"],
        authenticator_selection: params["authenticatorSelection"],
        exclude: exclude,
        extensions: params["extensions"],
        relying_party: self,
        user: user
      )
    end

    def verify_registration(params, challenge, user_verification: nil)
      credential = WebAuthn::Credential.from_create(params, relying_party: self)
      credential if credential.verify(challenge, user_verification: user_verification)
    end

    def options_for_authentication(params, allow:)
      WebAuthn::Credential.options_for_get(
        allow: allow,
        extensions: params["extensions"],
        relying_party: self,
        user_verification: params["userVerification"]
      )
    end

    def verify_authentication(params, challenge, public_key:, sign_count:, user_verification:)
      credential = WebAuthn::Credential.from_get(params, relying_party: self)
      credential if credential.verify(
        challenge,
        public_key: public_key,
        sign_count: sign_count,
        user_verification: user_verification
      )
    end
  end
end
