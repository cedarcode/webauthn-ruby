# frozen_string_literal: true

require "awrence"
require "json"
require "securerandom"

module WebAuthn
  class PublicKeyCredential
    class Options
      CHALLENGE_LENGTH = 32

      def self.from_json(json_string)
        hash = JSON.parse(json_string)
        from_hash(hash.to_snake_keys)
      end

      def self.from_hash(hash)
        options = new(
          timeout: hash["timeout"],
          extensions: hash["extensions"],
          **keyword_arguments_for_initialize(hash)
        )
        options.instance_variable_set(:@raw_challenge, WebAuthn.configuration.encoder.decode(hash["challenge"]))
        options
      end

      class << self
        alias_method :deserialize, :from_json
      end

      attr_reader :timeout, :extensions

      def initialize(timeout: default_timeout, extensions: nil)
        @timeout = timeout
        @extensions = extensions
      end

      def challenge
        encoder.encode(raw_challenge)
      end

      def raw_challenge
        @raw_challenge ||= SecureRandom.random_bytes(CHALLENGE_LENGTH)
      end

      # Argument wildcard for Ruby on Rails controller automatic object JSON serialization
      def as_json(*)
        to_hash.to_camelback_keys
      end

      def to_json(*_args)
        as_json.to_json
      end

      alias_method :serialize, :to_json

      private

      def to_hash
        hash = {}

        attributes.each do |attribute_name|
          value = send(attribute_name)

          if value.respond_to?(:as_json)
            value = value.as_json
          end

          if value
            hash[attribute_name] = value
          end
        end

        hash
      end

      def attributes
        [:challenge, :timeout, :extensions]
      end

      def encoder
        WebAuthn.configuration.encoder
      end

      def default_timeout
        configuration.credential_options_timeout
      end

      def configuration
        WebAuthn.configuration
      end

      def as_public_key_descriptors(ids)
        Array(ids).map { |id| { type: TYPE_PUBLIC_KEY, id: id } }
      end
    end
  end
end
