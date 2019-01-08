# frozen_string_literal: true

require "webauthn/error"

module WebAuthn
  class VerificationError < Error; end

  class InvalidAuthenticatorDataError < VerificationError; end
  class InvalidChallengeError < VerificationError; end
  class InvalidOriginError < VerificationError; end
  class InvalidRPIdError < VerificationError; end
  class InvalidTypeError < VerificationError; end
  class UserNotPresentError < VerificationError; end

  class AuthenticatorResponse
    def initialize(client_data_json:)
      @client_data_json = client_data_json
    end

    def verify(original_challenge, original_origin, rp_id: nil)
      valid_type? &&
        valid_challenge?(original_challenge) &&
        valid_origin?(original_origin) &&
        valid_rp_id?(rp_id || rp_id_from_origin(original_origin)) &&
        verify_authenticator_data &&
        verify_user_flagged
    end

    def valid?(*args)
      verify(*args)
    rescue WebAuthn::VerificationError
      false
    end

    def client_data
      @client_data ||= WebAuthn::ClientData.new(client_data_json)
    end

    private

    attr_reader :client_data_json

    def valid_type?
      client_data.type == type or raise WebAuthn::InvalidTypeError
    end

    def valid_challenge?(original_challenge)
      WebAuthn::SecurityUtils.secure_compare(Base64.urlsafe_decode64(client_data.challenge), original_challenge) or
        raise WebAuthn::InvalidChallengeError
    end

    def valid_origin?(original_origin)
      client_data.origin == original_origin or raise WebAuthn::InvalidOriginError
    end

    def valid_rp_id?(rp_id)
      OpenSSL::Digest::SHA256.digest(rp_id) == authenticator_data.rp_id_hash or raise WebAuthn::InvalidRPIdError
    end

    def verify_authenticator_data
      authenticator_data.valid? or raise WebAuthn::InvalidAuthenticatorDataError
    end

    def verify_user_flagged
      authenticator_data.user_flagged? or raise WebAuthn::UserNotPresentError
    end

    def rp_id_from_origin(original_origin)
      URI.parse(original_origin).host
    end

    def type
      raise NotImplementedError, "Please define #type method in subclass"
    end
  end
end
