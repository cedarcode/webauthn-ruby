# frozen_string_literal: true

module WebAuthn
  class PublicKeyCredential
    class Entity
      include Camelize

      attr_reader :name

      def initialize(name:)
        @name = name
      end

      def as_json
        deep_camelize_keys(to_hash)
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
        [:name]
      end
    end
  end
end
