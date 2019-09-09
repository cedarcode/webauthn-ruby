# frozen_string_literal: true

require "webauthn/credential_entity"

module WebAuthn
  class CredentialUserEntity < CredentialEntity
    attr_reader :id, :display_name

    def initialize(id:, display_name: nil, **keyword_arguments)
      super(**keyword_arguments)

      @id = id
      @display_name = display_name || name
    end
  end
end
