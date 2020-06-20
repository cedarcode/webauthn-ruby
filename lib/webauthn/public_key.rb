# frozen_string_literal: true

require "cose/algorithm"
require "cose/error"
require "cose/key"
require "cose/rsapkcs1_algorithm"
require "webauthn/attestation_statement/fido_u2f/public_key"

module WebAuthn
  class PublicKey
    class UnsupportedAlgorithm < Error; end

    def self.deserialize(public_key)
      cose_key =
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

      new(cose_key: cose_key)
    end

    attr_reader :cose_key

    def initialize(cose_key:)
      @cose_key = cose_key
    end

    def pkey
      @cose_key.to_pkey
    end

    def alg
      @cose_key.alg
    end

    def verify(signature, verification_data)
      cose_algorithm.verify(pkey, signature, verification_data)
    rescue COSE::Error
      false
    end

    private

    def cose_algorithm
      @cose_algorithm ||= COSE::Algorithm.find(alg) || raise(
        UnsupportedAlgorithm,
        "The public key algorithm #{alg} is not among the available COSE algorithms"
      )
    end
  end
end
