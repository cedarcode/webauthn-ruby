# frozen_string_literal: true

module WebAuthn
  module Metadata
    module Coercer
      class Objects
        def initialize(klass)
          @klass = klass
        end

        def coerce(values)
          return unless values.is_a?(Array)
          return values if values.all? { |value| value.is_a?(@klass) }

          values.map { |value| @klass.from_json(value) }
        end
      end
    end
  end
end
