# frozen_string_literal: true

require "cose/algorithm"
require "cose/key"
require "openssl"
require "tpm/constants"
require "tpm/s_attest"
require "tpm/t_public"
require "webauthn/attestation_statement/base"
require "webauthn/signature_verifier"

module WebAuthn
  module AttestationStatement
    class TPM < Base
      BYTE_LENGTH = 8
      CERTIFICATE_V3 = 2
      CERTIFICATE_EMPTY_NAME = OpenSSL::X509::Name.new([]).freeze

      COSE_TO_TPM_ALG = {
        COSE::Algorithm.by_name("ES256").id => ::TPM::ALG_ECDSA,
        COSE::Algorithm.by_name("RS256").id => ::TPM::ALG_RSASSA
      }.freeze

      COSE_TO_TPM_CURVE = {
        COSE::Key::EC2::CRV_P256 => ::TPM::ECC_NIST_P256
      }.freeze

      OID_TCG_KP_AIK_CERTIFICATE = "2.23.133.8.3"

      TPM_TO_OPENSSL_HASH_ALG = {
        ::TPM::ALG_SHA256 => "SHA256"
      }.freeze

      TPM_V2 = "2.0"

      def valid?(authenticator_data, client_data_hash)
        case attestation_type
        when ATTESTATION_TYPE_ATTCA
          att_to_be_signed = authenticator_data.data + client_data_hash

          ver == TPM_V2 &&
            valid_signature? &&
            valid_aik_certificate? &&
            valid_cert_info?(att_to_be_signed) &&
            valid_public_key?(authenticator_data.credential.public_key) &&
            matching_aaguid?(authenticator_data.attested_credential_data.aaguid) &&
            [attestation_type, attestation_trust_path]
        when ATTESTATION_TYPE_ECDAA
          raise(
            WebAuthn::AttestationStatement::Base::NotSupportedError,
            "Attestation type ECDAA is not supported"
          )
        end
      end

      private

      def valid_signature?
        WebAuthn::SignatureVerifier.new(alg, aik_certificate.public_key).verify(sig, verification_data)
      end

      def valid_aik_certificate?
        aik_certificate.version == CERTIFICATE_V3 &&
          aik_certificate.subject.eql?(CERTIFICATE_EMPTY_NAME) &&
          certificate_in_use?(aik_certificate) &&
          aik_certificate.extensions.find { |ext| ext.oid == 'basicConstraints' }&.value == "CA:FALSE" &&
          aik_certificate.extensions.find { |ext| ext.oid == "extendedKeyUsage" }&.value == OID_TCG_KP_AIK_CERTIFICATE
      end

      def valid_cert_info?(att_to_be_signed)
        cert_info.magic == ::TPM::GENERATED_VALUE &&
          cert_info.attested.name.buffer == [pub_area.name_alg].pack("n") + pub_area_hash &&
          cert_info.extra_data.buffer == OpenSSL::Digest.digest(algorithm.hash, att_to_be_signed)
      end

      def valid_public_key?(credential_public_key)
        cose_key = COSE::Key.deserialize(credential_public_key)

        case cose_key
        when COSE::Key::EC2
          valid_ecc_key?(cose_key)
        when COSE::Key::RSA
          valid_rsa_key?(cose_key)
        else
          raise "Unsupported or unknown TPM key type"
        end
      end

      def certificate_in_use?(certificate)
        now = Time.now

        certificate.not_before < now && now < certificate.not_after
      end

      def valid_ecc_key?(cose_key)
        pub_area.parameters.symmetric == ::TPM::ALG_NULL &&
          (pub_area.parameters.scheme == ::TPM::ALG_NULL || pub_area.parameters.scheme == COSE_TO_TPM_ALG[alg]) &&
          pub_area.parameters.curve_id == COSE_TO_TPM_CURVE[cose_key.crv] &&
          pub_area.unique.buffer == cose_key.x + cose_key.y
      end

      def valid_rsa_key?(cose_key)
        pub_area.parameters.symmetric == ::TPM::ALG_NULL &&
          (pub_area.parameters.scheme == ::TPM::ALG_NULL || pub_area.parameters.scheme == COSE_TO_TPM_ALG[alg]) &&
          pub_area.parameters.key_bits == cose_key.n.size * BYTE_LENGTH &&
          pub_area.unique.buffer == cose_key.n
      end

      def pub_area_hash
        OpenSSL::Digest.digest(TPM_TO_OPENSSL_HASH_ALG[pub_area.name_alg], statement["pubArea"])
      end

      def verification_data
        statement["certInfo"]
      end

      def aik_certificate
        attestation_certificate_chain[0]
      end

      alias_method :attestation_certificate, :aik_certificate

      def cert_info
        @cert_info ||= ::TPM::SAttest.read(statement["certInfo"])
      end

      def pub_area
        @pub_area ||= ::TPM::TPublic.read(statement["pubArea"])
      end

      def attestation_certificate_chain
        @attestation_certificate_chain ||= raw_certificates.map { |c| OpenSSL::X509::Certificate.new(c) }
      end

      def raw_certificates
        statement["x5c"]
      end

      def sig
        statement["sig"]
      end

      def ver
        statement["ver"]
      end

      def algorithm
        @algorithm ||= COSE::Algorithm.find(alg)
      end

      def alg
        statement["alg"]
      end

      def ecdaa_key_id
        statement["ecdaaKeyId"]
      end

      def attestation_type
        if raw_certificates && !ecdaa_key_id
          ATTESTATION_TYPE_ATTCA
        elsif ecdaa_key_id && !raw_certificates
          ATTESTATION_TYPE_ECDAA
        else
          raise "Attestation type invalid"
        end
      end

      def attestation_trust_path
        attestation_certificate_chain
      end
    end
  end
end
