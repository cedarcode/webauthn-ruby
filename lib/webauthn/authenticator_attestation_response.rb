# frozen_string_literal: true

require "cbor"
require "forwardable"
require "uri"
require "openssl"

require "webauthn/attestation"
require "webauthn/authenticator_response"
require "webauthn/client_data"
require "webauthn/encoder"

module WebAuthn
  class AttestationStatementVerificationError < VerificationError; end
  class AttestationTrustworthinessVerificationError < VerificationError; end
  class AttestationTypeVerificationError < VerificationError; end
  class AttestedCredentialVerificationError < VerificationError; end

  class AuthenticatorAttestationResponse < AuthenticatorResponse
    def self.from_client(response)
      encoder = WebAuthn.configuration.encoder

      new(
        attestation_object: encoder.decode(response["attestationObject"]),
        client_data_json: encoder.decode(response["clientDataJSON"])
      )
    end

    attr_reader :attestation_type, :attestation_trust_path

    def initialize(attestation_object:, **options)
      super(**options)

      @attestation_object = attestation_object
    end

    def verify(expected_challenge, expected_origin = nil, user_verification: nil, rp_id: nil)
      super

      verify_item(:attested_credential)
      if WebAuthn.configuration.verify_attestation_statement
        verify_item(:attestation_statement)
      end

      true
    end

    def attestation
      @attestation ||= WebAuthn::Attestation.deserialize(attestation_object)
    end

    extend Forwardable

    def_delegators(
      :attestation,
      :aaguid,
      :attestation_statement,
      :attestation_certificate_key_id,
      :authenticator_data,
      :credential
    )

    alias_method :attestation_certificate_key, :attestation_certificate_key_id

    private

    attr_reader :attestation_object

    def type
      WebAuthn::TYPES[:create]
    end

    def valid_attested_credential?
      attestation.valid_attested_credential?
    end

    def valid_attestation_statement?
      @attestation_type, @attestation_trust_path = attestation.valid_attestation_statement?(client_data.hash)
    end
  end
end
