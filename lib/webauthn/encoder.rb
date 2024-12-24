require "base64"

module WebAuthn
  module Config
    module Encoder
      # Default encoding type used for WebAuthn operations
      DEFAULT_ENCODING = :base64url

      # Supported encoding types and their corresponding Base64 methods
      ENCODINGS = {
        base64: :strict,
        base64url: :urlsafe
      }.freeze

      # Error message template for unsupported encoding types
      INVALID_ENCODING_ERROR = "Unsupported or unknown encoding: %s".freeze
    end
  end

  # Custom error class for encoding-related errors
  class EncodingError < StandardError; end

  # Handles encoding and decoding of WebAuthn data
  class Encoder
    attr_reader :encoding

    # Initialize encoder with specified encoding type
    # @param encoding [Symbol] the encoding type to use (:base64url by default)
    def initialize(encoding = Config::Encoder::DEFAULT_ENCODING)
      @encoding = encoding
    end

    # Encode data using the specified encoding type
    # @param data [String] the data to encode
    # @return [String] encoded data
    def encode(data)
      return data if skip_encoding?

      validate_encoding!
      send("encode_#{encoding}", data)
    end

    # Decode data using the specified encoding type
    # @param data [String] the data to decode
    # @return [String] decoded data
    def decode(data)
      return data if skip_encoding?

      validate_encoding!
      send("decode_#{encoding}", data)
    end

    private

    # Check if encoding should be skipped
    # @return [Boolean] true if encoding is nil or false
    def skip_encoding?
      encoding.nil? || encoding == false
    end

    # Validate that the current encoding type is supported
    # @raise [EncodingError] if encoding type is not supported
    def validate_encoding!
      return if Config::Encoder::ENCODINGS.key?(encoding)

      raise EncodingError, Config::Encoder::INVALID_ENCODING_ERROR % encoding
    end

    # Encode data using standard Base64 encoding
    # @param data [String] the data to encode
    # @return [String] Base64 encoded data
    def encode_base64(data)
      Base64.strict_encode64(data)
    end

    # Encode data using URL-safe Base64 encoding without padding
    # @param data [String] the data to encode
    # @return [String] URL-safe Base64 encoded data
    def encode_base64url(data)
      Base64.urlsafe_encode64(data, padding: false)
    end

    # Decode standard Base64 encoded data
    # @param data [String] the Base64 encoded data
    # @return [String] decoded data
    def decode_base64(data)
      Base64.strict_decode64(data)
    end

    # Decode URL-safe Base64 encoded data
    # @param data [String] the URL-safe Base64 encoded data
    # @return [String] decoded data
    def decode_base64url(data)
      Base64.urlsafe_decode64(ensure_padding(data))
    end

    # Ensure proper Base64 padding
    # @param data [String] the data to pad
    # @return [String] properly padded data
    def ensure_padding(data)
      return data if data.end_with?("=")

      data.ljust((data.length + 3) & ~3, "=")
    end
  end

  # Factory method to create a standard encoder instance
  # @return [Encoder] a new encoder instance with default settings
  def self.standard_encoder
    @standard_encoder ||= Encoder.new
  end
end
