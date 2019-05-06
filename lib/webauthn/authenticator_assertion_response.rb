# frozen_string_literal: true

require "cose/algorithm"
require "cose/key"
require "webauthn/attestation_statement/fido_u2f/public_key"
require "webauthn/authenticator_data"
require "webauthn/authenticator_response"
require "webauthn/client_utils"
require "webauthn/signature_verifier"

module WebAuthn
  class CredentialVerificationError < VerificationError; end
  class SignatureVerificationError < VerificationError; end

  class AuthenticatorAssertionResponse < AuthenticatorResponse
    def self.from_json(json, id)
      new(
        credential_id: id, # TODO: Remove this argument
        authenticator_data: WebAuthn::ClientUtils.decode(json["authenticatorData"]),
        client_data_json: WebAuthn::ClientUtils.decode(json["clientDataJSON"]),
        signature: WebAuthn::ClientUtils.decode(json["signature"])
      )
    end

    def initialize(credential_id:, authenticator_data:, signature:, **options)
      super(options)

      @credential_id = credential_id
      @authenticator_data_bytes = authenticator_data
      @signature = signature
    end

    def verify(expected_challenge, expected_origin = nil, allowed_credentials:, rp_id: nil)
      super(expected_challenge, expected_origin, rp_id: rp_id)

      verify_item(:credential, allowed_credentials)
      verify_item(:signature, credential_cose_key(allowed_credentials))

      true
    end

    def authenticator_data
      @authenticator_data ||= WebAuthn::AuthenticatorData.new(authenticator_data_bytes)
    end

    private

    attr_reader :credential_id, :authenticator_data_bytes, :signature

    def valid_signature?(credential_cose_key)
      WebAuthn::SignatureVerifier
        .new(credential_cose_key.alg, credential_cose_key.to_pkey)
        .verify(signature, authenticator_data_bytes + client_data.hash)
    end

    # TODO: Move this validation out of the scope of this class
    def valid_credential?(allowed_credentials)
      allowed_credential_ids = allowed_credentials.map { |credential| credential[:id] }

      allowed_credential_ids.include?(credential_id)
    end

    def credential_cose_key(allowed_credentials)
      matched_credential = allowed_credentials.find do |credential|
        credential[:id] == credential_id
      end

      if WebAuthn::AttestationStatement::FidoU2f::PublicKey.uncompressed_point?(matched_credential[:public_key])
        # Gem version v1.11.0 and lower, used to behave so that Credential#public_key
        # returned an EC P-256 uncompressed point.
        #
        # Because of https://github.com/cedarcode/webauthn-ruby/issues/137 this was changed
        # and Credential#public_key started returning the unchanged COSE_Key formatted
        # credentialPublicKey (as in https://www.w3.org/TR/webauthn/#credentialpublickey).
        #
        # Given that the credential public key is expected to be stored long-term by the gem
        # user and later be passed as one of the allowed_credentials arguments in the
        # AuthenticatorAssertionResponse.verify call, we then need to support the two formats.
        COSE::Key::EC2.new(
          alg: COSE::Algorithm.by_name("ES256").id,
          crv: 1,
          x: matched_credential[:public_key][1..32],
          y: matched_credential[:public_key][33..-1]
        )
      else
        COSE::Key.deserialize(matched_credential[:public_key])
      end
    end

    def type
      WebAuthn::TYPES[:get]
    end
  end
end
