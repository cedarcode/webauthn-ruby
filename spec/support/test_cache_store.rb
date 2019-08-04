# frozen_string_literal: true

# A very simple cache story for the test suite that mimics the ActiveSupport::Cache::Store interface
class TestCacheStore
  def initialize
    @store = {}
  end

  def read(name, _options = nil)
    @store[name]
  end

  def write(name, value, _options = nil)
    @store[name] = value
  end

  def delete(name, _options = nil)
    @store.delete(name)
  end

  def clear(_options = nil)
    @store.clear
  end
end
