# frozen_string_literal: true

require "webauthn/error"

module WebAuthn
  module AttestationStatement
    class Base
      class NotSupportedError < Error; end

      def initialize(statement)
        @statement = statement
      end

      def valid?(_authenticator_data, _client_data_hash)
        raise NotImpelementedError
      end

      private

      attr_reader :statement

      def algorithm
        statement["alg"]
      end

      def raw_attestation_certificates
        statement["x5c"]
      end

      def raw_ecdaa_key_id
        statement["ecdaaKeyId"]
      end

      def signature
        statement["sig"]
      end
    end
  end
end
