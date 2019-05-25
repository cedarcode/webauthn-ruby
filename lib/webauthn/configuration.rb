# frozen_string_literal: true

module WebAuthn
  def self.configuration
    @configuration ||= Configuration.new
  end

  def self.configure
    yield(configuration)
  end

  class Configuration
    DEFAULT_ALGORITHMS = ["ES256", "PS256", "RS256"].freeze

    attr_accessor :algorithms
    attr_accessor :origin
    attr_accessor :rp_id
    attr_accessor :rp_name

    def initialize
      @algorithms = DEFAULT_ALGORITHMS.dup
    end
  end
end
