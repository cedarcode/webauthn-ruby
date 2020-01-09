# frozen_string_literal: true

require "webauthn/attestation_statement/base"

module WebAuthn
  module AttestationStatement
    class None < Base
      def valid?(*_args)
        if statement == {}
          [WebAuthn::AttestationStatement::ATTESTATION_TYPE_NONE, nil]
        else
          false
        end
      end
    end
  end
end
