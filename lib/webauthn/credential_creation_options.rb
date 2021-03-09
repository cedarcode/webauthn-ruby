# frozen_string_literal: true

require "cose/algorithm"
require "webauthn/credential_options"
require "webauthn/credential_rp_entity"
require "webauthn/credential_user_entity"

module WebAuthn
  def self.credential_creation_options(rp_name: nil, user_name: "web-user", display_name: "web-user", user_id: "1")
    warn(
      "DEPRECATION WARNING: `WebAuthn.credential_creation_options` is deprecated."\
      " Please use `WebAuthn::Credential.options_for_create` instead."
    )

    CredentialCreationOptions.new(
      rp_name: rp_name, user_id: user_id, user_name: user_name, user_display_name: display_name
    ).to_h
  end

  class CredentialCreationOptions < CredentialOptions
    DEFAULT_RP_NAME = "web-server"

    attr_accessor :attestation, :authenticator_selection, :exclude_credentials, :extensions

    def initialize(
      attestation: nil,
      authenticator_selection: nil,
      exclude_credentials: nil,
      extensions: nil,
      user_id:,
      user_name:,
      user_display_name: nil,
      rp_name: nil
    )
      super()

      @attestation = attestation
      @authenticator_selection = authenticator_selection
      @exclude_credentials = exclude_credentials
      @extensions = extensions
      @user_id = user_id
      @user_name = user_name
      @user_display_name = user_display_name
      @rp_name = rp_name
    end

    def to_h
      options = {
        challenge: challenge,
        pubKeyCredParams: pub_key_cred_params,
        timeout: timeout,
        user: { id: user.id, name: user.name, displayName: user.display_name },
        rp: { name: rp.name }
      }

      if attestation
        options[:attestation] = attestation
      end

      if authenticator_selection
        options[:authenticatorSelection] = authenticator_selection
      end

      if exclude_credentials
        options[:excludeCredentials] = exclude_credentials
      end

      if extensions
        options[:extensions] = extensions
      end

      options
    end

    def pub_key_cred_params
      configuration.algorithms.map do |alg_name|
        { type: "public-key", alg: COSE::Algorithm.by_name(alg_name).id }
      end
    end

    def rp
      @rp ||= CredentialRPEntity.new(name: rp_name || configuration.rp_name || DEFAULT_RP_NAME)
    end

    def user
      @user ||= CredentialUserEntity.new(id: user_id, name: user_name, display_name: user_display_name)
    end

    private

    attr_reader :user_id, :user_name, :user_display_name, :rp_name

    def configuration
      WebAuthn.configuration
    end
  end
end
