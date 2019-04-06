# frozen_string_literal: true

require "webauthn/error"

module WebAuthn
  class VerificationError < Error; end
  # `UnspecifiedRpIdError` is a caller error rather than an error in the webauthn
  # response. So we directly subclass `Error`.
  class UnspecifiedRpIdError < Error; end

  class AuthenticatorDataVerificationError < VerificationError; end
  class ChallengeVerificationError < VerificationError; end
  class OriginVerificationError < VerificationError; end
  class RpIdVerificationError < VerificationError; end
  class TokenBindingVerificationError < VerificationError; end
  class TypeVerificationError < VerificationError; end
  class UserPresenceVerificationError < VerificationError; end

  class AuthenticatorResponse
    def initialize(client_data_json:)
      @client_data_json = client_data_json
    end

    def verify(expected_challenge, expected_origin=nil, rp_id: nil)
      if rp_id.nil?
        if expected_origin.nil?
          raise WebAuthn::UnspecifiedRpIdError
        end
        rp_id = URI.parse(expected_origin).host
      end

      verify_item(:type)
      verify_item(:challenge, expected_challenge)
      verify_item(:origin, rp_id, expected_origin)
      verify_item(:rp_id, rp_id)
      verify_item(:authenticator_data)
      verify_item(:user_presence)

      true
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
      WebAuthn::SecurityUtils.secure_compare(Base64.urlsafe_decode64(client_data.challenge), expected_challenge)
    end

    def valid_origin?(rp_id, expected_origin)
      # If the caller specifies the expected origin, check that it exactly matches the signed origin.
      return false unless expected_origin.nil? || client_data.origin == expected_origin

      origin = URI.parse(client_data.origin)
      # Per https://www.w3.org/TR/webauthn/#rp-id
      # - The RP ID must be equal to the origin's effective domain, or a registrable domain suffix of the origin's effective domain.
      #   - The calculation of "registrable domain suffix" is specified at:
      #     https://html.spec.whatwg.org/multipage/origin.html#is-a-registrable-domain-suffix-of-or-is-equal-to
      # - The origin's scheme must be https.
      # - The origin's port is unrestricted.
      return false unless origin.host == rp_id || origin.host.end_with?("." + rp_id)
      origin.scheme == "https"
    end

    def valid_rp_id?(rp_id)
      # TODO: rp_id cannot be a public suffix
      OpenSSL::Digest::SHA256.digest(rp_id) == authenticator_data.rp_id_hash
    end

    def valid_authenticator_data?
      authenticator_data.valid?
    end

    def valid_user_presence?
      authenticator_data.user_flagged?
    end

    def type
      raise NotImplementedError, "Please define #type method in subclass"
    end
  end
end
