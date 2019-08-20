# frozen_string_literal: true

require "webauthn/public_key_credential/entity"

module WebAuthn
  class PublicKeyCredential
    class UserEntity < Entity
      attr_reader :id, :display_name

      def initialize(id:, display_name: nil, **keyword_arguments)
        super(**keyword_arguments)

        @id = id
        @display_name = display_name || name
      end

      private

      def attributes
        super.concat([:id, :display_name])
      end
    end
  end
end
