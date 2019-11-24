# frozen_string_literal: true

require "cose/algorithm"
require "cose/key"
require "webauthn/attestation_statement/fido_u2f/public_key"
require "webauthn/authenticator_data"
require "webauthn/authenticator_response"
require "webauthn/encoder"
require "webauthn/signature_verifier"

module WebAuthn
  class SignatureVerificationError < VerificationError; end
  class SignCountVerificationError < VerificationError; end

  class AuthenticatorAssertionResponse < AuthenticatorResponse
    def self.from_client(response)
      encoder = WebAuthn.configuration.encoder

      user_handle =
        if response["userHandle"]
          encoder.decode(response["userHandle"])
        end

      new(
        authenticator_data: encoder.decode(response["authenticatorData"]),
        client_data_json: encoder.decode(response["clientDataJSON"]),
        signature: encoder.decode(response["signature"]),
        user_handle: user_handle
      )
    end

    attr_reader :user_handle

    def initialize(authenticator_data:, signature:, user_handle: nil, **options)
      super(**options)

      @authenticator_data_bytes = authenticator_data
      @signature = signature
      @user_handle = user_handle
    end

    def verify(expected_challenge, expected_origin = nil, public_key:, sign_count:, user_verification: nil,
               rp_id: nil)
      super(expected_challenge, expected_origin, user_verification: user_verification, rp_id: rp_id)
      verify_item(:signature, credential_cose_key(public_key))
      verify_item(:sign_count, sign_count)

      true
    end

    def authenticator_data
      @authenticator_data ||= WebAuthn::AuthenticatorData.new(authenticator_data_bytes)
    end

    private

    attr_reader :authenticator_data_bytes, :signature

    def valid_signature?(credential_cose_key)
      WebAuthn::SignatureVerifier
        .new(credential_cose_key.alg, credential_cose_key.to_pkey)
        .verify(signature, authenticator_data_bytes + client_data.hash)
    end

    def valid_sign_count?(stored_sign_count)
      normalized_sign_count = stored_sign_count || 0
      if authenticator_data.sign_count.nonzero? || normalized_sign_count.nonzero?
        authenticator_data.sign_count > normalized_sign_count
      else
        true
      end
    end

    def credential_cose_key(public_key)
      if WebAuthn::AttestationStatement::FidoU2f::PublicKey.uncompressed_point?(public_key)
        # Gem version v1.11.0 and lower, used to behave so that Credential#public_key
        # returned an EC P-256 uncompressed point.
        #
        # Because of https://github.com/cedarcode/webauthn-ruby/issues/137 this was changed
        # and Credential#public_key started returning the unchanged COSE_Key formatted
        # credentialPublicKey (as in https://www.w3.org/TR/webauthn/#credentialpublickey).
        #
        # Given that the credential public key is expected to be stored long-term by the gem
        # user and later be passed as the public_key argument in the
        # AuthenticatorAssertionResponse.verify call, we then need to support the two formats.
        COSE::Key::EC2.new(
          alg: COSE::Algorithm.by_name("ES256").id,
          crv: 1,
          x: public_key[1..32],
          y: public_key[33..-1]
        )
      else
        COSE::Key.deserialize(public_key)
      end
    end

    def type
      WebAuthn::TYPES[:get]
    end
  end
end
