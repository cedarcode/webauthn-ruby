# frozen_string_literal: true

require "webauthn/attestation_statement/base"

module WebAuthn
  module AttestationStatement
    class None < Base
      def valid?(*_args)
        true
      end
    end
  end
end
