# frozen_string_literal: true

require "spec_helper"

require "android_safetynet/attestation_response"
require "base64"
require "jwt"
require "openssl"

RSpec.describe "AttestationResponse" do
  context "#verify" do
    let(:attestation_response) { AndroidSafetynet::AttestationResponse.new(response) }

    let(:response) do
      JWT.encode(
        payload,
        attestation_key,
        "ES256",
        x5c: [Base64.strict_encode64(leaf_certificate)]
      )
    end

    let(:payload) { { nonce: nonce, timestampMs: timestamp * 1000 } }
    let(:attestation_key) { OpenSSL::PKey::EC.new("prime256v1").generate_key }

    let(:leaf_certificate) do
      certificate = OpenSSL::X509::Certificate.new
      certificate.subject = OpenSSL::X509::Name.new([["CN", leaf_certificate_subject_common_name]])
      certificate.not_before = Time.now
      certificate.not_after = Time.now + 60
      certificate.public_key = attestation_key

      certificate.sign(attestation_key, OpenSSL::Digest::SHA256.new)

      certificate.to_der
    end

    let(:leaf_certificate_subject_common_name) { "attest.android.com" }
    let(:nonce) { rand(16).to_s }
    let(:timestamp) { Time.now.to_i }

    it "returns true if everything's in place" do
      expect(attestation_response.verify(nonce)).to be_truthy
    end

    context "when nonce don't match with the one in the response" do
      it "fails" do
        expect {
          attestation_response.verify(nonce + "something else")
        }.to raise_error(AndroidSafetynet::AttestationResponse::NonceMismatchError)
      end
    end

    context "when response is nil" do
      let(:response) { nil }

      it "fails" do
        expect {
          attestation_response.verify(nonce)
        }.to raise_error(AndroidSafetynet::AttestationResponse::ResponseMissingError)
      end
    end

    context "when the certificate chain is invalid" do
      context "because leaf certificate issuer hostmane is invalid" do
        let(:leaf_certificate_subject_common_name) { "notattest.android.com" }

        it "fails" do
          expect {
            attestation_response.verify(nonce)
          }.to raise_error(AndroidSafetynet::AttestationResponse::LeafCertificateSubjectError)
        end
      end
    end

    context "when the signature is invalid" do
      context "because it was signed with a different key" do
        let(:response) do
          JWT.encode(
            payload,
            OpenSSL::PKey::EC.new("prime256v1").generate_key,
            "ES256",
            x5c: [Base64.strict_encode64(leaf_certificate)]
          )
        end

        it "fails" do
          expect {
            attestation_response.verify(nonce)
          }.to raise_error(AndroidSafetynet::AttestationResponse::SignatureError)
        end
      end
    end
  end
end
