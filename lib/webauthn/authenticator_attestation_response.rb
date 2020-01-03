# frozen_string_literal: true

require "cbor"
require "forwardable"
require "uri"
require "openssl"

require "webauthn/attestation_object"
require "webauthn/authenticator_response"
require "webauthn/client_data"
require "webauthn/encoder"

module WebAuthn
  class AttestationStatementVerificationError < VerificationError; end
  class AttestationTrustworthinessVerificationError < VerificationError; end
  class AttestedCredentialVerificationError < VerificationError; end

  class AuthenticatorAttestationResponse < AuthenticatorResponse
    extend Forwardable

    def self.from_client(response, relying_party: WebAuthn.configuration.relying_party)
      encoder = relying_party.encoder

      new(
        attestation_object: encoder.decode(response["attestationObject"]),
        client_data_json: encoder.decode(response["clientDataJSON"]),
        relying_party: relying_party
      )
    end

    attr_reader :attestation_type, :attestation_trust_path

    def initialize(attestation_object:, **options)
      super(**options)

      @attestation_object_bytes = attestation_object
      @relying_party = relying_party
    end

    def verify(expected_challenge, expected_origin = nil, user_verification: nil, rp_id: nil)
      super

      verify_item(:attested_credential)
      if relying_party.verify_attestation_statement
        verify_item(:attestation_statement)
      end

      true
    end

    def attestation_object
      @attestation_object ||= WebAuthn::AttestationObject.deserialize(attestation_object_bytes, relying_party)
    end

    def_delegators(
      :attestation_object,
      :aaguid,
      :attestation_statement,
      :attestation_certificate_key_id,
      :authenticator_data,
      :credential
    )

    alias_method :attestation_certificate_key, :attestation_certificate_key_id

    private

    attr_reader :relying_party

    def type
      WebAuthn::TYPES[:create]
    end

    def valid_attested_credential?
      attestation_object.valid_attested_credential?
    end

    def valid_attestation_statement?
      @attestation_type, @attestation_trust_path = attestation_object.valid_attestation_statement?(client_data.hash)
    end
  end
end
