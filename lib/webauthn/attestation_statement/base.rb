# frozen_string_literal: true

require "webauthn/attestation_statement/types"

module WebAuthn
  module AttestationStatement
    class Base
      class NotSupportedError < StandardError; end

      def initialize(statement)
        @statement = statement
      end

      def valid?(_authenticator_data, _client_data_hash)
        raise NotImpelementedError
      end

      private

      attr_reader :statement
    end
  end
end
