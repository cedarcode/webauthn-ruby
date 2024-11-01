# frozen_string_literal: true

require "securerandom"

module WebAuthn
  class PublicKeyCredential
    class Options
      include JSONSerializer

      CHALLENGE_LENGTH = 32

      attr_reader :timeout, :extensions, :relying_party

      def initialize(timeout: nil, extensions: nil, relying_party: WebAuthn.configuration.relying_party)
        @relying_party = relying_party
        @timeout = timeout || default_timeout
        @extensions = default_extensions.merge(extensions || {})
      end

      def challenge
        encoder.encode(raw_challenge)
      end

      private

      def attributes
        [:challenge, :timeout, :extensions]
      end

      def encoder
        relying_party.encoder
      end

      def raw_challenge
        @raw_challenge ||= SecureRandom.random_bytes(CHALLENGE_LENGTH)
      end

      def default_timeout
        relying_party.credential_options_timeout
      end

      def default_extensions
        {}
      end

      def as_public_key_descriptors(ids)
        Array(ids).map { |id| { type: TYPE_PUBLIC_KEY, id: id } }
      end
    end
  end
end
