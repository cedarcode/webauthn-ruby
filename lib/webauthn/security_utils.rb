# frozen_string_literal: true

require "securecompare"

module WebAuthn
  module SecurityUtils
    # Constant time string comparison, for variable length strings.
    # This code was adapted from Rails ActiveSupport::SecurityUtils
    #
    # The values are first processed by SHA256, so that we don't leak length info
    # via timing attacks.
    def secure_compare(first_string, second_string)
      first_string_sha256 = ::Digest::SHA256.digest(first_string)
      second_string_sha256 = ::Digest::SHA256.digest(second_string)

      SecureCompare.compare(first_string_sha256, second_string_sha256) && first_string == second_string
    end
    module_function :secure_compare
  end
end
