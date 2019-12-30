# frozen_string_literal: true

require "webauthn/credential"

module WebAuthn
  class RelyingParty
    def initialize(
      algorithms: nil, encoding: nil, origin: nil, id: nil, name: nil,
      verify_attestation_statement: nil, credential_options_timeout: nil,
      silent_authentication: nil, acceptable_attestation_types: nil,
      attestation_root_certificates_finders: nil
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

    attr_writer :algorithms, :encoding, :origin, :id, :name,
                :verify_attestation_statement, :credential_options_timeout,
                :silent_authentication, :acceptable_attestation_types

    def algorithms
      @algorithms || WebAuthn.configuration.algorithms
    end

    def encoding
      @encoding || WebAuthn.configuration.encoding
    end

    def origin
      @origin || WebAuthn.configuration.origin
    end

    def id
      @id || WebAuthn.configuration.rp_id
    end

    def name
      @name || WebAuthn.configuration.rp_name
    end

    def verify_attestation_statement
      @verify_attestation_statement || WebAuthn.configuration.verify_attestation_statement
    end

    def credential_options_timeout
      @credential_options_timeout || WebAuthn.configuration.credential_options_timeout
    end

    def silent_authentication
      @silent_authentication || WebAuthn.configuration.silent_authentication
    end

    def acceptable_attestation_types
      @acceptable_attestation_types || WebAuthn.configuration.acceptable_attestation_types
    end

    def attestation_root_certificates_finders
      @attestation_root_certificates_finders || WebAuthn.configuration.attestation_root_certificates_finders
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

    def generate_user_id
      WebAuthn.generate_user_id
    end

    def encoder
      @encoder ||= WebAuthn::Encoder.new(encoding)
    end

    def options_for_registration(params, user:, exclude:)
      WebAuthn::Credential.options_for_create(
        attestation: params["attestation"],
        authenticator_selection: params["authenticatorSelection"],
        exclude: exclude,
        extensions: params["extensions"],
        rp: to_hash,
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
        rp_id: id,
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

    private

    def to_hash
      {
        id: id,
        name: name
      }
    end
  end
end
