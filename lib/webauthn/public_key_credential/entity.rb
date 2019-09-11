# frozen_string_literal: true

require "awrence"
require "plissken"

module WebAuthn
  class PublicKeyCredential
    class Entity
      def self.attributes
        [:name, :icon]
      end

      def self.from_json(entity)
        hash = {}
        attributes.each do |attribute_name|
          hash[attribute_name] = entity[attribute_name]
        end
        new(hash.to_snake_keys)
      end

      attr_reader :name, :icon

      def initialize(name:, icon: nil)
        @name = name
        @icon = icon
      end

      def as_json
        to_hash.to_camelback_keys
      end

      private

      def to_hash
        hash = {}

        self.class.attributes.each do |attribute_name|
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
    end
  end
end
