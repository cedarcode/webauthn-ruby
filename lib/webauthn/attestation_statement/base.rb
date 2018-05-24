# frozen_string_literal: true

module WebAuthn
  module AttestationStatement
    class Base
      def initialize(statement)
        @statement = statement
      end

      def valid?(*args)
        raise NotImpelementedError
      end

      private

      attr_reader :statement
    end
  end
end
