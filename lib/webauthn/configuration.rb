# frozen_string_literal: true

require 'webauthn/relying_party'

module WebAuthn
  def self.configuration
    @configuration ||= RelyingParty.new
  end

  def self.configure
    yield(configuration)
  end
end
