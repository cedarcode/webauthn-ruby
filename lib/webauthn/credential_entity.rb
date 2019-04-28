# frozen_string_literal: true

module WebAuthn
  class CredentialEntity
    attr_reader :name

    def initialize(name:)
      @name = name
    end
  end
end
