# frozen_string_literal: true

module WebAuthn
  class FidoU2fAttestationStatementVerification
    def initialize(attestation_statement:, authenticator_data:, client_data_hash:)
      @attestation_statement = attestation_statement
      @authenticator_data = authenticator_data
      @client_data_hash = client_data_hash
    end

    def successful?
      attestation_statement.valid? && valid_signature?
      # return type and trust path?
    end

    private

    attr_reader :attestation_statement, :authenticator_data, :client_data_hash

    def valid_signature?
      attestation_statement
        .certificate_public_key
        .verify(
          "SHA256",
          attestation_statement.signature,
          verification_data
        )
    end

    def verification_data
      "\x00" +
        authenticator_data.rp_id_hash +
        client_data_hash +
        authenticator_data.credential_id +
        public_key_u2f
    end

    def public_key_u2f
      "\x04" + x + y
    end

    def x
      credential_public_key[-2]
    end

    def y
      credential_public_key[-3]
    end

    def credential_public_key
      authenticator_data.credential_public_key
    end
  end
end
