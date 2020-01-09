# frozen_string_literal: true

require "delegate"
require "openssl"
require "tpm/constants"

module TPM
  # Section 3.2 in https://www.trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
  class EKCertificate < SimpleDelegator
    ASN_V3 = 2
    EMPTY_NAME = OpenSSL::X509::Name.new([]).freeze
    SAN_DIRECTORY_NAME = 4
    OID_TCG_AT_TPM_MANUFACTURER = "2.23.133.2.1"
    OID_TCG_AT_TPM_MODEL = "2.23.133.2.2"
    OID_TCG_AT_TPM_VERSION = "2.23.133.2.3"
    OID_TCG_KP_AIK_CERTIFICATE = "2.23.133.8.3"

    def self.from_der(certificate_der)
      new(OpenSSL::X509::Certificate.new(certificate_der))
    end

    def conformant?
      in_use? &&
        valid_version? &&
        valid_extended_key_usage? &&
        valid_basic_constraints? &&
        valid_subject_alternative_name?
    end

    def empty_subject?
      subject.eql?(EMPTY_NAME)
    end

    private

    def in_use?
      now = Time.now

      not_before < now && now < not_after
    end

    def valid_version?
      version == ASN_V3
    end

    def valid_basic_constraints?
      basic_constraints = extension("basicConstraints")

      basic_constraints && basic_constraints.value == "CA:FALSE" && basic_constraints.critical?
    end

    def valid_extended_key_usage?
      extended_key_usage = extension("extendedKeyUsage")

      extended_key_usage && extended_key_usage.value == OID_TCG_KP_AIK_CERTIFICATE && !extended_key_usage.critical?
    end

    def valid_subject_alternative_name?
      extension = extensions.detect { |ext| ext.oid == "subjectAltName" }
      return unless extension

      san_asn1 =
        OpenSSL::ASN1.decode(extension).find do |val|
          val.tag_class == :UNIVERSAL && val.tag == OpenSSL::ASN1::OCTET_STRING
        end
      directory_name =
        OpenSSL::ASN1.decode(san_asn1.value).find do |val|
          val.tag_class == :CONTEXT_SPECIFIC && val.tag == SAN_DIRECTORY_NAME
        end
      name = OpenSSL::X509::Name.new(directory_name.value.first).to_a
      manufacturer = name.assoc(OID_TCG_AT_TPM_MANUFACTURER).at(1)
      model = name.assoc(OID_TCG_AT_TPM_MODEL).at(1)
      version = name.assoc(OID_TCG_AT_TPM_VERSION).at(1)

      ::TPM::VENDOR_IDS[manufacturer] &&
        !model.empty? &&
        !version.empty? &&
        (empty_subject? && extension.critical? || !empty_subject? && !extension.critical?)
    end

    def extension(oid)
      extensions.detect { |ext| ext.oid == oid }
    end
  end
end
