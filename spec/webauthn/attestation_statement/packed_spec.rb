# frozen_string_literal: true

require 'base64'
require 'webauthn/attestation_statement/packed'

RSpec.describe WebAuthn::AttestationStatement::Packed do
  let(:attestation_object) {
    CBOR.decode(
      Base64.strict_decode64(
        seeds[:security_key_packed_x5c][:authenticator_attestation_response][:attestation_object]
      )
    )
  }
  let(:client_data_hash) {
    Base64.strict_decode64(
      seeds[:security_key_packed_x5c][:authenticator_attestation_response][:client_data_hash]
    )
  }
  let(:statement) { attestation_object['attStmt'] }
  let(:authenticator_data) { double('authData', data: attestation_object['authData'], credential: nil) }

  subject do
    described_class.new(statement)
  end

  it "is valid if everything's in place" do
    attestation_type, attestation_trust_path = subject.valid?(authenticator_data, client_data_hash)
    expect(attestation_type).to eq("Basic_or_AttCA")
    expect(attestation_trust_path).to all(be_kind_of(OpenSSL::X509::Certificate))
  end
end
