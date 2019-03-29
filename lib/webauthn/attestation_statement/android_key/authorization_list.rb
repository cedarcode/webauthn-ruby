# frozen_string_literal: true

require "webauthn/attestation_statement/base"

module WebAuthn
  module AttestationStatement
    class AndroidKey < Base
      class AuthorizationList
        PURPOSE_TAG = 1
        ALL_APPLICATIONS_TAG = 600
        ORIGIN_TAG = 702

        def initialize(sequence)
          @sequence = sequence
        end

        def purpose
          find_by_tag(PURPOSE_TAG)&.value&.at(0)&.value&.at(0)&.value
        end

        def all_applications
          find_by_tag(ALL_APPLICATIONS_TAG)&.value
        end

        def origin
          find_by_tag(ORIGIN_TAG)&.value&.at(0)&.value
        end

        private

        attr_reader :sequence

        def find_by_tag(tag)
          sequence.detect { |data| data.tag == tag }
        end
      end
    end
  end
end
