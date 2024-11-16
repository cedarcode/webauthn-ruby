# frozen_string_literal: true

require "webauthn/authenticator_data"
require "webauthn/client_data"
require "webauthn/error"

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
    def initialize(client_data_json:, relying_party: WebAuthn.configuration.relying_party)
      @client_data_json = client_data_json
      @relying_party = relying_party
    end

    def verify(expected_challenge, expected_origin = nil, user_presence: nil, user_verification: nil, rp_id: nil)
      expected_origin ||= relying_party.allowed_origins ||
                          [relying_party.origin] ||
                          raise("Unspecified expected origin")

      rp_id ||= relying_party.id

      verify_item(:type)
      verify_item(:token_binding)
      verify_item(:challenge, expected_challenge)
      verify_item(:origin, expected_origin)
      verify_item(:authenticator_data)

      # NOTE: we are trying to guess from 'expected_origin' only in case it's a single origin
      # (array that contains a single element)
      # rp_id should either be explicitly set or guessed from only a single origin
      verify_item(
        :rp_id,
        rp_id || rp_id_from_origin(expected_origin)
      )

      # Fallback to RP configuration unless user_presence is passed in explicitely
      if user_presence.nil? && !relying_party.silent_authentication || user_presence
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

    attr_reader :client_data_json, :relying_party

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
      OpenSSL.secure_compare(client_data.challenge, expected_challenge)
    end

    # @return [Boolean]
    # @param [Array<String>] expected_origin
    # Validate if one of the allowed origins configured for RP is matching the one received from client
    def valid_origin?(expected_origin)
      return false unless expected_origin

      expected_origin.include?(client_data.origin)
    end

    # @return [Boolean]
    # @param [String] rp_id
    # Validate if RP ID is matching the one received from client
    def valid_rp_id?(rp_id)
      return false unless rp_id

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

    # @return [String, nil]
    # @param [String, Array, nil] expected_origin
    # Extract RP ID from origin in case rp_id is not provided explicitly
    def rp_id_from_origin(expected_origin)
      case expected_origin
      when Array
        URI.parse(expected_origin.first).host if expected_origin.size == 1
      when String
        URI.parse(expected_origin).host
      end
    end

    def type
      raise NotImplementedError, "Please define #type method in subclass"
    end
  end
end
