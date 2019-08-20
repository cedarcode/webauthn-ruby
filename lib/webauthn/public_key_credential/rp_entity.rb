# frozen_string_literal: true

require "webauthn/public_key_credential/entity"

module WebAuthn
  class PublicKeyCredential
    class RPEntity < Entity
      attr_reader :id

      def initialize(id: nil, **keyword_arguments)
        super(**keyword_arguments)

        @id = id
      end

      private

      def attributes
        super.concat([:id])
      end
    end
  end
end
