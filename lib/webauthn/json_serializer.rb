# frozen_string_literal: true

module WebAuthn
  module JSONSerializer
    # Argument wildcard for Ruby on Rails controller automatic object JSON serialization
    def as_json(*)
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

    def deep_camelize_keys(object)
      if object.is_a?(Hash)
        object.each_with_object({}) do |(key, value), result|
          result[camelize(key)] = deep_camelize_keys(value)
        end
      else
        object
      end
    end

    def camelize(term)
      first_term, *rest = term.to_s.split('_')

      [first_term, *rest.map(&:capitalize)].join.to_sym
    end
  end
end
