# frozen_string_literal: true

module WebAuthn
  class AuthenticatorData
    MIN_LENGTH = 37
    USER_PRESENT_FLAG_POSITION = 0

    def initialize(data)
      @data = data
    end

    def valid?
      data.length >= MIN_LENGTH
    end

    def user_present?
      flags[USER_PRESENT_FLAG_POSITION] == "1"
    end

    private

    attr_reader :data

    def flags
      @flags ||= data[32].unpack("b*").first
    end
  end
end
