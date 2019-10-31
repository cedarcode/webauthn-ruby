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
        store.purpose = OpenSSL::X509::PURPOSE_ANY
        store.flags = OpenSSL::X509::V_FLAG_CRL_CHECK | OpenSSL::X509::V_FLAG_CRL_CHECK_ALL
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
        get = Net::HTTP::Get.new(uri, DEFAULT_HEADERS)
        response = http(uri).request(get)
        response.value
        response.body
      end

      def http(uri)
        @http ||= begin
          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = uri.port == 443
          http.verify_mode = OpenSSL::SSL::VERIFY_PEER
          http.open_timeout = 5
          http.read_timeout = 5
          http
        end
      end

      def verified_public_key(x5c, trust_store)
        certificates = x5c.map do |encoded|
          OpenSSL::X509::Certificate.new(Base64.strict_decode64(encoded))
        end
        leaf_certificate = certificates[0]
        chain_certificates = certificates[1..-1]

        crls = download_crls(certificates)
        crls.each do |crl|
          trust_store.add_crl(crl)
        end

        if trust_store.verify(leaf_certificate, chain_certificates)
          leaf_certificate.public_key
        else
          raise(UnverifiedSigningKeyError, "OpenSSL error #{trust_store.error} (#{trust_store.error_string})")
        end
      end

      def download_crls(certificates)
        uris = extract_crl_distribution_points(certificates)

        crls = uris.compact.uniq.map do |uri|
          begin
            get(uri)
          rescue Net::ProtoServerError
            # TODO: figure out why test endpoint specifies a missing and unused CRL in the cert chain, and see if this
            # rescue can be removed. If the CRL is used, OpenSSL error 3 (unable to get certificate CRL) will raise.
            nil
          end
        end
        crls.compact.map { |crl| OpenSSL::X509::CRL.new(crl) }
      end

      def extract_crl_distribution_points(certificates)
        certificates.map do |certificate|
          extension = certificate.extensions.detect { |ext| ext.oid == "crlDistributionPoints" }
          # TODO: replace this with proper parsing of deeply nested ASN1 structures
          match = extension&.value&.match(/URI:(?<uri>\S*)/)
          URI(match[:uri]) if match
        end
      end
    end
  end
end
