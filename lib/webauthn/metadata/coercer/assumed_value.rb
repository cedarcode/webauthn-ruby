# frozen_string_literal: true

module WebAuthn
  module Metadata
    module Coercer
      class AssumedValue
        def initialize(assume)
          @assume = assume
        end

        def coerce(value)
          if value.nil?
            @assume
          else
            value
          end
        end
      end
    end
  end
end
