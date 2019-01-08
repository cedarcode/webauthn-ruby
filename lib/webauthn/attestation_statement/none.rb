# frozen_string_literal: true

require "webauthn/attestation_statement/base"

module WebAuthn
  module AttestationStatement
    class None < Base
      def valid?(*_args)
        [WebAuthn::AttestationStatement::ATTESTATION_TYPE_NONE, nil]
      end
    end
  end
end
