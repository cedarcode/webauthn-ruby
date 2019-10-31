# frozen_string_literal: true

module WebAuthn
  module Metadata
    module Coercer
      class MagicNumber
        def initialize(mapping, array: false)
          @mapping = mapping
          @array = array
        end

        def coerce(values)
          if @array
            return values unless values.all? { |value| value.is_a?(Integer) }

            values.map { |value| @mapping[value] }.compact
          else
            return values unless values.is_a?(Integer)

            @mapping[values]
          end
        end
      end
    end
  end
end
