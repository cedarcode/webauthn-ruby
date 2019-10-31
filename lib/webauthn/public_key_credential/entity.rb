# frozen_string_literal: true

require "awrence"

module WebAuthn
  class PublicKeyCredential
    class Entity
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
        [:name, :icon]
      end
    end
  end
end
