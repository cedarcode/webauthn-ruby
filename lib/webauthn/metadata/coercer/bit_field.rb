# frozen_string_literal: true

module WebAuthn
  module Metadata
    module Coercer
      class BitField
        def initialize(mapping, single_value: false)
          @mapping = mapping
          @single_value = single_value
        end

        def coerce(value)
          results = @mapping.reject { |flag, _constant| flag & value == 0 }.values

          if @single_value
            results.first
          else
            results
          end
        end
      end
    end
  end
end
