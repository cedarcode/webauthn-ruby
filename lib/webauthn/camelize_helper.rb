# frozen_string_literal: true

module WebAuthn
  module CamelizeHelper
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
