# frozen_string_literal: true

module WebAuthn
  def self.configuration
    @configuration ||= Configuration.new
  end

  def self.configure
    yield(configuration)
  end

  class Configuration
    attr_accessor :origin
    attr_accessor :rp_id
    attr_accessor :rp_name
  end
end
