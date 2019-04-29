# frozen_string_literal: true

require "jwt"

module AndroidSafetynet
  # Decoupled from WebAuthn, candidate for extraction
  # Reference: https://developer.android.com/training/safetynet/attestation.html
  class AttestationResponse
    class VerificationError < StandardError; end
    class LeafCertificateSubjectError < VerificationError; end
    class NonceMismatchError < VerificationError; end
    class SignatureError < VerificationError; end
    class ResponseMissingError < VerificationError; end

    CERTIRICATE_CHAIN_HEADER = "x5c"
    VALID_SUBJECT_HOSTNAME = "attest.android.com"
    HEADERS_POSITION = 1
    PAYLOAD_POSITION = 0

    attr_reader :response

    def initialize(response)
      @response = response
    end

    def verify(nonce)
      if response
        valid_nonce?(nonce) || raise(NonceMismatchError)
        valid_attestation_domain? || raise(LeafCertificateSubjectError)
        valid_signature? || raise(SignatureError)
      else
        raise(ResponseMissingError)
      end
    end

    def cts_profile_match?
      payload["ctsProfileMatch"]
    end

    def certificate_chain
      @certificate_chain ||= headers[CERTIRICATE_CHAIN_HEADER].map do |cert|
        OpenSSL::X509::Certificate.new(Base64.strict_decode64(cert))
      end
    end

    private

    def valid_nonce?(nonce)
      WebAuthn::SecurityUtils.secure_compare(payload["nonce"], nonce)
    end

    def valid_attestation_domain?
      common_name = leaf_certificate&.subject&.to_a&.assoc('CN')

      if common_name
        common_name[1] == VALID_SUBJECT_HOSTNAME
      end
    end

    def valid_signature?
      JWT.decode(response, leaf_certificate.public_key, true, algorithms: ["ES256", "RS256"])
    rescue JWT::VerificationError
      false
    end

    def leaf_certificate
      certificate_chain[0]
    end

    def headers
      jws_parts[HEADERS_POSITION]
    end

    def payload
      jws_parts[PAYLOAD_POSITION]
    end

    def jws_parts
      @jws_parts ||= JWT.decode(response, nil, false)
    end
  end
end
