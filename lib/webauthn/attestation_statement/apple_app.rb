# frozen_string_literal: true

require "openssl"
require "webauthn/attestation_statement/base"

module WebAuthn
  module AttestationStatement
    class AppleApp < Base
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

      # appattest followed by seven 0x00 bytes
      AAGUID_PRODUCTION = "61707061-7474-6573-7400-000000000000"

      # appattestdevelop
      AAGUID_DEVELOPMENT = "61707061-7474-6573-7464-6576656c6f70"

      ## https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server
      def valid?(authenticator_data, client_data_hash)
        ## 1. Verify that the x5c array contains the intermediate and
        ## leaf certificates for App Attest, starting from the
        ## credential certificate in the first data buffer in the
        ## array (credcert). Verify the validity of the certificates
        ## using Apple’s App Attest root certificate.
        trustworthy? &&
          # steps 2, 3, 4
          valid_nonce?(authenticator_data, client_data_hash) &&
          ## step 5. Create the SHA256 hash of the public key in credCert,
          ## and verify that it matches the key identifier from your
          ## app.
          matching_public_key?(authenticator_data) &&
          ## 6. Compute the SHA256 hash of your app’s App ID, and
          ## verify that it’s the same as the authenticator data’s RP
          ## ID hash.
          matching_rp_id?(authenticator_data) &&
          ## 7. Verify that the authenticator data’s counter field equals 0.
          counter_zero?(authenticator_data) &&
          ## 8. Verify that the authenticator data’s aaguid field is
          ## either appattestdevelop if operating in the development
          ## environment, or appattest followed by seven 0x00 bytes if
          ## operating in the production environment.
          valid_aaguid?(authenticator_data) &&
          ## 9. Verify that the authenticator data’s credentialId field is the same as the key identifier.
          valid_credential_id?(authenticator_data) &&
          [attestation_type, attestation_trust_path]
      end

      private

      ## 2. Create clientDataHash as the SHA256 hash of the one-time
      ## challenge your server sends to your app before performing the
      ## attestation, and append that hash to the end of the
      ## authenticator data (authData from the decoded object).

      ## 3. Generate a new SHA256 hash of the composite item to create nonce

      ## 4. Obtain the value of the credCert extension with OID
      ## 1.2.840.113635.100.8.2, which is a DER-encoded ASN.1
      ## sequence. Decode the sequence and extract the single octet
      ## string that it contains. Verify that the string equals nonce.
      def valid_nonce?(authenticator_data, client_data_hash)
        extension = cred_cert.find_extension(NONCE_EXTENSION_OID)

        sequence = OpenSSL::ASN1.decode(extension.value_der)

        sequence.tag == OpenSSL::ASN1::SEQUENCE &&
          sequence.value.size == 1 &&
          sequence.value[0].value[0].value ==
            OpenSSL::Digest::SHA256.digest(authenticator_data.data + client_data_hash)
      end

      def matching_rp_id?(authenticator_data)
        authenticator_data.rp_id_hash == OpenSSL::Digest::SHA256.digest(WebAuthn.configuration.rp_id)
      end

      def counter_zero?(authenticator_data)
        authenticator_data.sign_count.zero?
      end

      def valid_aaguid?(authenticator_data)
        expected_aaguid =
          WebAuthn.configuration.development_mode ? AAGUID_DEVELOPMENT : AAGUID_PRODUCTION

        authenticator_data.aaguid == expected_aaguid
      end

      def valid_credential_id?(_authenticator_data)
        # TODO: how to implement this when we don't have access to the key_id a this stage?

        # authenticator_data.credential.id == key_id

        true
      end

      # https://www.w3.org/TR/webauthn/#sctn-attestation-types
      def attestation_type
        # used by Android SafetyNet and webauthn4j AppleApp implementation
        WebAuthn::AttestationStatement::ATTESTATION_TYPE_BASIC
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
