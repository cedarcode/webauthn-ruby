# frozen_string_literal: true

require "spec_helper"
require "webauthn/security_utils"

RSpec.describe WebAuthn::SecurityUtils do
  describe "#secure_compare" do
    it "returns true if the two strings are equal" do
      expect(WebAuthn::SecurityUtils.secure_compare("a", "a")).to be true
    end

    it "returns false if the two strings are not equal" do
      expect(WebAuthn::SecurityUtils.secure_compare("a", "b")).to be false
    end

    it "returns false if the two strings are not equal length" do
      expect(WebAuthn::SecurityUtils.secure_compare("a", "aa")).to be false
    end
  end
end
