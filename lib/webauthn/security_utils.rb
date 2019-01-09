# frozen_string_literal: true

module WebAuthn
  module SecurityUtils
    # Constant time string comparison, for variable length strings.
    # This code was adapted from Rails ActiveSupport::SecurityUtils
    #
    # The values are first processed by SHA256, so that we don't leak length info
    # via timing attacks.
    def secure_compare(first_string, second_string)
      first_string_sha256 = ::Digest::SHA256.hexdigest(first_string)
      second_string_sha256 = ::Digest::SHA256.hexdigest(second_string)
      fixed_length_secure_compare(first_string_sha256, second_string_sha256) && first_string == second_string
    end
    module_function :secure_compare

    private

    # Constant time string comparison, for fixed length strings.
    # This code was adapted from Rails ActiveSupport::SecurityUtils
    #
    # The values compared should be of fixed length, such as strings
    # that have already been processed by HMAC. Raises in case of length mismatch.
    def fixed_length_secure_compare(first_string, second_string)
      raise ArgumentError, "string length mismatch." unless first_string.bytesize == second_string.bytesize

      l = first_string.unpack "C#{first_string.bytesize}"

      res = 0
      second_string.each_byte { |byte| res |= byte ^ l.shift }
      res == 0
    end
    module_function :fixed_length_secure_compare
  end
end
