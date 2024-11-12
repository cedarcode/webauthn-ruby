# frozen_string_literal: true

module WebAuthn
  class PublicKeyCredential
    class Entity
      include JSONSerializer

      attr_reader :name

      def initialize(name:)
        @name = name
      end

      private

      def attributes
        [:name]
      end
    end
  end
end
