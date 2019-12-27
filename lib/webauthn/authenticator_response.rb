# frozen_string_literal: true

require "webauthn/authenticator_data"
require "webauthn/client_data"
require "webauthn/error"
require "webauthn/security_utils"

module WebAuthn
  TYPES = { create: "webauthn.create", get: "webauthn.get" }.freeze

  class VerificationError < Error; end

  class AuthenticatorDataVerificationError < VerificationError; end
  class ChallengeVerificationError < VerificationError; end
  class OriginVerificationError < VerificationError; end
  class RpIdVerificationError < VerificationError; end
  class TokenBindingVerificationError < VerificationError; end
  class TypeVerificationError < VerificationError; end
  class UserPresenceVerificationError < VerificationError; end
  class UserVerifiedVerificationError < VerificationError; end

  class AuthenticatorResponse
    def initialize(client_data_json:)
      @client_data_json = client_data_json
    end

    def verify(expected_challenge, expected_origin = nil, user_verification: nil, rp_id: nil)
      expected_origin ||= relying_party.origin || raise("Unspecified expected origin")
      rp_id ||= relying_party.id

      verify_item(:type)
      verify_item(:token_binding)
      verify_item(:challenge, expected_challenge)
      verify_item(:origin, expected_origin)
      verify_item(:authenticator_data)
      verify_item(:rp_id, rp_id || rp_id_from_origin(expected_origin))

      if !relying_party.silent_authentication
        verify_item(:user_presence)
      end

      if user_verification
        verify_item(:user_verified)
      end

      true
    end

    def valid?(*args, **keyword_arguments)
      verify(*args, **keyword_arguments)
    rescue WebAuthn::VerificationError
      false
    end

    def client_data
      @client_data ||= WebAuthn::ClientData.new(client_data_json)
    end

    private

    attr_reader :client_data_json

    def verify_item(item, *args)
      if send("valid_#{item}?", *args)
        true
      else
        camelized_item = item.to_s.split('_').map { |w| w.capitalize }.join
        error_const_name = "WebAuthn::#{camelized_item}VerificationError"
        raise Object.const_get(error_const_name)
      end
    end

    def valid_type?
      client_data.type == type
    end

    def valid_token_binding?
      client_data.valid_token_binding_format?
    end

    def valid_challenge?(expected_challenge)
      WebAuthn::SecurityUtils.secure_compare(client_data.challenge, expected_challenge)
    end

    def valid_origin?(expected_origin)
      expected_origin && (client_data.origin == expected_origin)
    end

    def valid_rp_id?(rp_id)
      OpenSSL::Digest::SHA256.digest(rp_id) == authenticator_data.rp_id_hash
    end

    def valid_authenticator_data?
      authenticator_data.valid?
    rescue WebAuthn::AuthenticatorDataFormatError
      false
    end

    def valid_user_presence?
      authenticator_data.user_flagged?
    end

    def valid_user_verified?
      authenticator_data.user_verified?
    end

    def rp_id_from_origin(expected_origin)
      URI.parse(expected_origin).host
    end

    def type
      raise NotImplementedError, "Please define #type method in subclass"
    end
  end
end
