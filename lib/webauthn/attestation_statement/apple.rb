# frozen_string_literal: true

require "openssl"
require "webauthn/attestation_statement/base"

module WebAuthn
  module AttestationStatement
    class Apple < Base
      # Source: https://www.apple.com/certificateauthority/private/
      ROOT_CERTIFICATE =
        OpenSSL::X509::Certificate.new(<<~PEM)
          -----BEGIN CERTIFICATE-----
          MIICEjCCAZmgAwIBAgIQaB0BbHo84wIlpQGUKEdXcTAKBggqhkjOPQQDAzBLMR8w
          HQYDVQQDDBZBcHBsZSBXZWJBdXRobiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJ
          bmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIwMDMxODE4MjEzMloXDTQ1MDMx
          NTAwMDAwMFowSzEfMB0GA1UEAwwWQXBwbGUgV2ViQXV0aG4gUm9vdCBDQTETMBEG
          A1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTB2MBAGByqGSM49
          AgEGBSuBBAAiA2IABCJCQ2pTVhzjl4Wo6IhHtMSAzO2cv+H9DQKev3//fG59G11k
          xu9eI0/7o6V5uShBpe1u6l6mS19S1FEh6yGljnZAJ+2GNP1mi/YK2kSXIuTHjxA/
          pcoRf7XkOtO4o1qlcaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUJtdk
          2cV4wlpn0afeaxLQG2PxxtcwDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2cA
          MGQCMFrZ+9DsJ1PW9hfNdBywZDsWDbWFp28it1d/5w2RPkRX3Bbn/UbDTNLx7Jr3
          jAGGiQIwHFj+dJZYUJR786osByBelJYsVZd2GbHQu209b5RCmGQ21gpSAk9QZW4B
          1bWeT0vT
          -----END CERTIFICATE-----
        PEM

      NONCE_EXTENSION_OID = "1.2.840.113635.100.8.2"

      def valid?(authenticator_data, client_data_hash)
        valid_nonce?(authenticator_data, client_data_hash) &&
          matching_public_key?(authenticator_data) &&
          trustworthy? &&
          [attestation_type, attestation_trust_path]
      end

      private

      def valid_nonce?(authenticator_data, client_data_hash)
        extension = cred_cert&.find_extension(NONCE_EXTENSION_OID)

        if extension
          sequence = OpenSSL::ASN1.decode(extension.value_der)

          sequence.tag == OpenSSL::ASN1::SEQUENCE &&
            sequence.value.size == 1 &&
            sequence.value[0].value[0].value ==
              OpenSSL::Digest::SHA256.digest(authenticator_data.data + client_data_hash)
        end
      end

      def attestation_type
        WebAuthn::AttestationStatement::ATTESTATION_TYPE_ANONCA
      end

      def cred_cert
        attestation_certificate
      end

      def default_root_certificates
        [ROOT_CERTIFICATE]
      end
    end
  end
end
