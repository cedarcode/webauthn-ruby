# frozen_string_literal: true

module WebAuthn
  module Camelize
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
      term.to_s
          .sub(/^(?:(?-mix:(?=a)b)(?=\b|[A-Z_])|\w)/) { |match| match.downcase }
          .gsub(/(?:_|(\/))([a-z\d]*)/i) do
        $2.capitalize
      end.to_sym
    end
  end
end
