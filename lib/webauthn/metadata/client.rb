# frozen_string_literal: true

require "jwt"
require "net/http"

module WebAuthn
  module Metadata
    class Client
      class DataIntegrityError < StandardError; end
      class InvalidHashError < DataIntegrityError; end
      class UnverifiedSigningKeyError < DataIntegrityError; end

      DEFAULT_HEADERS = {
        "Content-Type" => "application/json",
        "User-Agent" => "webauthn/#{WebAuthn::VERSION} (Ruby)"
      }.freeze

      def self.fido_trust_store
        store = OpenSSL::X509::Store.new
        file = File.read(File.join(__dir__, "Root.cer"))
        store.add_cert(OpenSSL::X509::Certificate.new(file))
      end

      def initialize(token)
        @token = token
      end

      def download_toc(uri, trust_store: self.class.fido_trust_store)
        response = get_with_token(uri)
        payload, _ = JWT.decode(response, nil, true, algorithms: ["ES256"]) do |headers|
          verified_public_key(headers["x5c"], trust_store)
        end
        payload
      end

      def download_entry(uri, expected_hash:)
        response = get_with_token(uri)
        unless SecureCompare.compare(OpenSSL::Digest::SHA256.digest(response), Base64.urlsafe_decode64(expected_hash))
          raise(InvalidHashError)
        end

        decoded_body = Base64.urlsafe_decode64(response)
        JSON.parse(decoded_body)
      end

      private

      def get_with_token(uri)
        if @token && !@token.empty?
          uri.path += "/" unless uri.path.end_with?("/")
          uri.query = "token=#{@token}"
        end
        get(uri)
      end

      def get(uri)
        get = Net::HTTP::Get.new(uri.request_uri, DEFAULT_HEADERS)
        response = build_http(uri).request(get)
        response.value || response.body
      end

      def build_http(uri)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.port == 443
        http.verify_mode = OpenSSL::SSL::VERIFY_PEER
        http.open_timeout = 5
        http.read_timeout = 5
        http
      end

      def verified_public_key(x5c, trust_store)
        certificates = x5c.map do |encoded|
          OpenSSL::X509::Certificate.new(Base64.strict_decode64(encoded))
        end
        leaf_certificate = certificates[0]
        chain_certificates = certificates[1..-1]

        if trust_store.verify(leaf_certificate, chain_certificates)
          leaf_certificate.public_key
        else
          raise(UnverifiedSigningKeyError, "OpenSSL error #{trust_store.error} (#{trust_store.error_string})")
        end
      end
    end
  end
end
