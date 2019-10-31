# frozen_string_literal: true

module WebAuthn
  module Metadata
    module Attributes
      def underscore_name(name)
        name
          .gsub(/([A-Z]+)([A-Z][a-z])/, '\1_\2')
          .gsub(/([a-z\d])([A-Z])/, '\1_\2')
          .downcase
          .to_sym
      end
      private :underscore_name

      def json_accessor(name, coercer = nil)
        underscored_name = underscore_name(name)
        attr_accessor underscored_name

        if coercer
          define_method(:"#{underscored_name}=") do |value|
            coerced_value = coercer.coerce(value)
            instance_variable_set(:"@#{underscored_name}", coerced_value)
          end
        end
      end

      def from_json(hash = {})
        instance = new
        hash.each do |k, v|
          method_name = :"#{underscore_name(k)}="
          instance.public_send(method_name, v) if instance.respond_to?(method_name)
        end

        instance
      end
    end
  end
end
