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
          MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
          JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
          QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
          Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
          biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
          bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
          NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
          Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
          MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
          CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
          53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
          oyFraWVIyd/dganmrduC1bmTBGwD
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
        extension = cred_cert&.extensions&.detect { |ext| ext.oid == NONCE_EXTENSION_OID }

        if extension
          sequence = OpenSSL::ASN1.decode(OpenSSL::ASN1.decode(extension.to_der).value[1].value)

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
