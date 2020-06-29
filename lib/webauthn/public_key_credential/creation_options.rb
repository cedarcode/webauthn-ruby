# frozen_string_literal: true

require "cose/algorithm"
require "webauthn/public_key_credential/options"
require "webauthn/public_key_credential/rp_entity"
require "webauthn/public_key_credential/user_entity"

module WebAuthn
  class PublicKeyCredential
    class CreationOptions < Options
      attr_accessor(
        :attestation,
        :authenticator_selection,
        :exclude,
        :algs,
        :rp,
        :user
      )

      def initialize(
        attestation: nil,
        authenticator_selection: nil,
        exclude_credentials: nil,
        exclude: nil,
        pub_key_cred_params: nil,
        algs: nil,
        rp: {},
        user:,
        **keyword_arguments
      )
        super(**keyword_arguments)

        @attestation = attestation
        @authenticator_selection = authenticator_selection
        @exclude_credentials = exclude_credentials
        @exclude = exclude
        @pub_key_cred_params = pub_key_cred_params
        @algs = algs

        @rp =
          if rp.is_a?(Hash)
            rp[:name] ||= relying_party.name
            rp[:id] ||= relying_party.id

            RPEntity.new(**rp)
          else
            rp
          end

        @user =
          if user.is_a?(Hash)
            UserEntity.new(**user)
          else
            user
          end
      end

      def exclude_credentials
        @exclude_credentials || exclude_credentials_from_exclude
      end

      def pub_key_cred_params
        @pub_key_cred_params || pub_key_cred_params_from_algs
      end

      private

      def attributes
        super.concat([:rp, :user, :pub_key_cred_params, :attestation, :authenticator_selection, :exclude_credentials])
      end

      def exclude_credentials_from_exclude
        if exclude
          as_public_key_descriptors(exclude)
        end
      end

      def pub_key_cred_params_from_algs
        Array(algs || relying_party.algorithms).map do |alg|
          alg_id =
            if alg.is_a?(String) || alg.is_a?(Symbol)
              COSE::Algorithm.by_name(alg.to_s).id
            else
              alg
            end

          { type: TYPE_PUBLIC_KEY, alg: alg_id }
        end
      end
    end
  end
end
