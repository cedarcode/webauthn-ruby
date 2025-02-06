# frozen_string_literal: true

require 'webauthn/fake_client'
require 'webauthn/attestation_statement/fido_u2f'

module WebAuthn
  class U2fMigrator
    def initialize(app_id:, certificate:, key_handle:, public_key:, counter:)
      @app_id = app_id
      @certificate = certificate
      @key_handle = key_handle
      @public_key = public_key
      @counter = counter
    end

    def authenticator_data
      @authenticator_data ||= WebAuthn::FakeAuthenticator::AuthenticatorData.new(
        rp_id_hash: OpenSSL::Digest::SHA256.digest(@app_id.to_s),
        credential: {
          id: credential_id,
          public_key: credential_cose_key
        },
        sign_count: @counter,
        user_present: true,
        user_verified: false,
        aaguid: WebAuthn::AuthenticatorData::AttestedCredentialData::ZEROED_AAGUID
      )
    end

    def credential
      @credential ||=
        begin
          hash = authenticator_data.send(:credential)
          WebAuthn::AuthenticatorData::AttestedCredentialData::Credential.new(
            id: hash[:id],
            public_key: hash[:public_key].serialize
          )
        end
    end

    def attestation_type
      WebAuthn::AttestationStatement::ATTESTATION_TYPE_BASIC_OR_ATTCA
    end

    def attestation_trust_path
      @attestation_trust_path ||= [OpenSSL::X509::Certificate.new(base64_strict_decode64(@certificate))]
    end

    private

    def base64_strict_decode64(data)
      data.unpack1("m0")
    end

    def base64_urlsafe_decode64(data)
      if !data.end_with?("=") && data.length % 4 != 0
        data = data.ljust((data.length + 3) & ~3, "=")
        data.tr!("-_", "+/")
      else
        data = data.tr("-_", "+/")
      end
      data.unpack1("m0")
    end

    # https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-client-to-authenticator-protocol-v2.0-rd-20180702.html#u2f-authenticatorMakeCredential-interoperability
    # Let credentialId be a credentialIdLength byte array initialized with CTAP1/U2F response key handle bytes.
    def credential_id
      base64_urlsafe_decode64(@key_handle)
    end

    # Let x9encodedUserPublicKey be the user public key returned in the U2F registration response message [U2FRawMsgs].
    # Let coseEncodedCredentialPublicKey be the result of converting x9encodedUserPublicKey’s value from ANS X9.62 /
    # Sec-1 v2 uncompressed curve point representation [SEC1V2] to COSE_Key representation ([RFC8152] Section 7).
    def credential_cose_key
      decoded_public_key = base64_strict_decode64(@public_key)
      if WebAuthn::AttestationStatement::FidoU2f::PublicKey.uncompressed_point?(decoded_public_key)
        COSE::Key::EC2.new(
          alg: COSE::Algorithm.by_name("ES256").id,
          crv: 1,
          x: decoded_public_key[1..32],
          y: decoded_public_key[33..-1]
        )
      else
        raise "expected U2F public key to be in uncompressed point format"
      end
    end
  end
end
