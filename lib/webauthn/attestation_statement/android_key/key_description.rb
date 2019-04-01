# frozen_string_literal: true

require "webauthn/attestation_statement/android_key/authorization_list"
require "webauthn/attestation_statement/base"

module WebAuthn
  module AttestationStatement
    class AndroidKey < Base
      class KeyDescription
        # https://developer.android.com/training/articles/security-key-attestation#certificate_schema
        ATTESTATION_CHALLENGE_INDEX = 4
        SOFTWARE_ENFORCED_INDEX = 6
        TEE_ENFORCED_INDEX = 7

        def initialize(sequence)
          @sequence = sequence
        end

        def attestation_challenge
          sequence[ATTESTATION_CHALLENGE_INDEX].value
        end

        def tee_enforced
          @tee_enforced ||= AuthorizationList.new(sequence[TEE_ENFORCED_INDEX].value)
        end

        def software_enforced
          @software_enforced ||= AuthorizationList.new(sequence[SOFTWARE_ENFORCED_INDEX].value)
        end

        private

        attr_reader :sequence
      end
    end
  end
end
