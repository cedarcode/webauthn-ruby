# frozen_string_literal: true

require "cose/algorithm"
require "webauthn/credential_options"
require "webauthn/credential_rp_entity"
require "webauthn/credential_user_entity"

module WebAuthn
  # TODO: make keyword arguments mandatory in next major version
  def self.credential_creation_options(rp_name: nil, user_name: "web-user", display_name: "web-user", user_id: "1")
    CredentialCreationOptions.new(
      rp_name: rp_name, user_id: user_id, user_name: user_name, user_display_name: display_name
    ).to_h
  end

  class CredentialCreationOptions < CredentialOptions
    DEFAULT_ALGORITHMS = ["ES256", "RS256"].freeze
    DEFAULT_RP_NAME = "web-server"

    DEFAULT_PUB_KEY_CRED_PARAMS = DEFAULT_ALGORITHMS.map do |alg_name|
      { type: "public-key", alg: COSE::Algorithm.by_name(alg_name).id }
    end.freeze

    def initialize(user_id:, user_name:, user_display_name: nil, rp_name: nil)
      @user_id = user_id
      @user_name = user_name
      @user_display_name = user_display_name
      @rp_name = rp_name
    end

    def to_h
      {
        challenge: challenge,
        pubKeyCredParams: pub_key_cred_params,
        user: { id: user.id, name: user.name, displayName: user.display_name },
        rp: { name: rp.name }
      }
    end

    def pub_key_cred_params
      DEFAULT_PUB_KEY_CRED_PARAMS
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
