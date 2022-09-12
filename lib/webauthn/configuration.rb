# frozen_string_literal: true

require 'forwardable'
require 'webauthn/relying_party'

module WebAuthn
  def self.configuration
    @configuration ||= Configuration.new
  end

  def self.configure
    yield(configuration)
  end

  class Configuration
    extend Forwardable

    def_delegators :@relying_party,
                   :algorithms,
                   :algorithms=,
                   :encoding,
                   :encoding=,
                   :origin,
                   :origin=,
                   :verify_attestation_statement,
                   :verify_attestation_statement=,
                   :credential_options_timeout,
                   :credential_options_timeout=,
                   :silent_authentication,
                   :silent_authentication=,
                   :acceptable_attestation_types,
                   :acceptable_attestation_types=,
                   :attestation_root_certificates_finders,
                   :attestation_root_certificates_finders=,
                   :encoder,
                   :encoder=

    attr_reader :relying_party

    def initialize
      @relying_party = RelyingParty.new
    end

    def rp_name
      relying_party.name
    end

    def rp_name=(name)
      relying_party.name = name
    end

    def rp_id
      relying_party.id
    end

    def rp_id=(id)
      relying_party.id = id
    end
  end
end
