# frozen_string_literal: true

require "webauthn/error"

module WebAuthn
  module AttestationStatement
    class Base
      class NotSupportedError < Error; end

      AAGUID_EXTENSION_OID = "1.3.6.1.4.1.45724.1.1.4"

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
