# frozen_string_literal: true

require "spec_helper"
require "support/seeds"
require "webauthn/attestation_statement/fido_u2f/public_key"
require "webauthn/authenticator_assertion_response"
require "webauthn/u2f_migrator"

RSpec.describe WebAuthn::AuthenticatorAssertionResponse do
  let(:client) { WebAuthn::FakeClient.new(actual_origin, encoding: false) }

  let!(:credential) { create_credential(client: client) }
  let(:credential_public_key) { credential[1] }

  let(:origin) { fake_origin }
  let(:actual_origin) { origin }
  let(:original_challenge) { fake_challenge }
  let(:assertion) { client.get(challenge: original_challenge) }
  let(:authenticator_data) { assertion["response"]["authenticatorData"] }

  let(:assertion_response) do
    WebAuthn::AuthenticatorAssertionResponse.new(
      client_data_json: assertion["response"]["clientDataJSON"],
      authenticator_data: authenticator_data,
      signature: assertion["response"]["signature"]
    )
  end

  before do
    WebAuthn.configuration.origin = origin
  end

  context "when everything's in place" do
    it "verifies" do
      expect(
        assertion_response.verify(original_challenge, public_key: credential_public_key, sign_count: 0)
      ).to be_truthy
    end

    it "is valid" do
      expect(
        assertion_response.valid?(original_challenge, public_key: credential_public_key, sign_count: 0)
      ).to be_truthy
    end
  end

  # Gem version v1.11.0 and lower, used to behave so that Credential#public_key
  # returned an EC P-256 uncompressed point.
  #
  # Because of https://github.com/cedarcode/webauthn-ruby/issues/137 this was changed
  # and Credential#public_key started returning the unchanged COSE_Key formatted
  # credentialPublicKey (as in https://www.w3.org/TR/webauthn/#credentialpublickey).
  #
  # Given that the credential public key is expected to be stored long-term by the gem
  # user and later be passed as the public_key argument in the
  # AuthenticatorAssertionResponse.verify call, we then need to support the two formats.
  context "when everything's in place with the old public key format" do
    it "verifies" do
      old_format_key =
        WebAuthn::AttestationStatement::FidoU2f::PublicKey
        .new(credential_public_key)
        .to_uncompressed_point

      expect(assertion_response.verify(original_challenge, public_key: old_format_key, sign_count: 0)).to be_truthy
    end
  end

  context "if signature was signed with a different key" do
    let(:different_public_key) do
      _different_id, different_public_key = create_credential(client: client)
      different_public_key
    end

    it "is invalid" do
      expect(assertion_response.valid?(original_challenge, public_key: different_public_key, sign_count: 0)).to be_falsy
    end

    it "doesn't verify" do
      expect {
        assertion_response.verify(original_challenge, public_key: different_public_key, sign_count: 0)
      }.to raise_exception(WebAuthn::SignatureVerificationError)
    end
  end

  describe "type validation" do
    context "if type is create instead of get" do
      before do
        allow(client).to receive(:type_for).and_return("webauthn.create")
      end

      it "doesn't verify" do
        expect {
          assertion_response.verify(original_challenge, public_key: credential_public_key, sign_count: 0)
        }.to raise_exception(WebAuthn::TypeVerificationError)
      end

      it "is invalid" do
        expect(
          assertion_response.valid?(original_challenge, public_key: credential_public_key, sign_count: 0)
        ).to be_falsy
      end
    end
  end

  describe "user present validation" do
    context "when user presence flag is off" do
      let(:assertion) { client.get(challenge: original_challenge, user_present: false, user_verified: false) }

      context "when silent_authentication is not set" do
        context 'when user presence is not set' do
          it "doesn't verify" do
            expect {
              assertion_response.verify(original_challenge, public_key: credential_public_key, sign_count: 0)
            }.to raise_exception(WebAuthn::UserPresenceVerificationError)
          end

          it "is invalid" do
            expect(
              assertion_response.valid?(original_challenge, public_key: credential_public_key, sign_count: 0)
            ).to be_falsy
          end
        end

        context 'when user presence is not required' do
          it "verifies if user presence is not required" do
            expect(
              assertion_response.verify(
                original_challenge,
                public_key: credential_public_key,
                sign_count: 0,
                user_presence: false
              )
            ).to be_truthy
          end

          it "is valid" do
            expect(
              assertion_response.valid?(
                original_challenge,
                public_key: credential_public_key,
                sign_count: 0,
                user_presence: false
              )
            ).to be_truthy
          end
        end

        context 'when user presence is required' do
          it "doesn't verify" do
            expect {
              assertion_response.verify(
                original_challenge,
                public_key: credential_public_key,
                sign_count: 0,
                user_presence: true
              )
            }.to raise_exception(WebAuthn::UserPresenceVerificationError)
          end

          it "is invalid" do
            expect(
              assertion_response.valid?(
                original_challenge,
                public_key: credential_public_key,
                sign_count: 0,
                user_presence: true
              )
            ).to be_falsy
          end
        end
      end

      context "when silent_authentication is disabled" do
        around do |ex|
          old_value = WebAuthn.configuration.silent_authentication
          WebAuthn.configuration.silent_authentication = false

          ex.run

          WebAuthn.configuration.silent_authentication = old_value
        end

        context 'when user presence is not set' do
          it "doesn't verify" do
            expect {
              assertion_response.verify(original_challenge, public_key: credential_public_key, sign_count: 0)
            }.to raise_exception(WebAuthn::UserPresenceVerificationError)
          end

          it "is invalid" do
            expect(
              assertion_response.valid?(original_challenge, public_key: credential_public_key, sign_count: 0)
            ).to be_falsy
          end
        end

        context 'when user presence is not required' do
          it "verifies if user presence is not required" do
            expect(
              assertion_response.verify(
                original_challenge,
                public_key: credential_public_key,
                sign_count: 0,
                user_presence: false
              )
            ).to be_truthy
          end

          it "is valid" do
            expect(
              assertion_response.valid?(
                original_challenge,
                public_key: credential_public_key,
                sign_count: 0,
                user_presence: false
              )
            ).to be_truthy
          end
        end

        context 'when user presence is required' do
          it "doesn't verify" do
            expect {
              assertion_response.verify(
                original_challenge,
                public_key: credential_public_key,
                sign_count: 0,
                user_presence: true
              )
            }.to raise_exception(WebAuthn::UserPresenceVerificationError)
          end

          it "is invalid" do
            expect(
              assertion_response.valid?(
                original_challenge,
                public_key: credential_public_key,
                sign_count: 0,
                user_presence: true
              )
            ).to be_falsy
          end
        end
      end

      context "when silent_authentication is enabled" do
        around do |ex|
          old_value = WebAuthn.configuration.silent_authentication
          WebAuthn.configuration.silent_authentication = true

          ex.run

          WebAuthn.configuration.silent_authentication = old_value
        end

        context 'when user presence is not set' do
          it "verifies if user presence is not required" do
            expect(
              assertion_response.verify(original_challenge, public_key: credential_public_key, sign_count: 0)
            ).to be_truthy
          end

          it "is valid" do
            expect(
              assertion_response.valid?(original_challenge, public_key: credential_public_key, sign_count: 0)
            ).to be_truthy
          end
        end

        context 'when user presence is not required' do
          it "verifies if user presence is not required" do
            expect(
              assertion_response.verify(
                original_challenge,
                public_key: credential_public_key,
                sign_count: 0,
                user_presence: false
              )
            ).to be_truthy
          end

          it "is valid" do
            expect(
              assertion_response.valid?(
                original_challenge,
                public_key: credential_public_key,
                sign_count: 0,
                user_presence: false
              )
            ).to be_truthy
          end
        end

        context 'when user presence is required' do
          it "doesn't verify" do
            expect {
              assertion_response.verify(
                original_challenge,
                public_key: credential_public_key,
                sign_count: 0,
                user_presence: true
              )
            }.to raise_exception(WebAuthn::UserPresenceVerificationError)
          end

          it "is invalid" do
            expect(
              assertion_response.valid?(
                original_challenge,
                public_key: credential_public_key,
                sign_count: 0,
                user_presence: true
              )
            ).to be_falsy
          end
        end
      end
    end
  end

  describe "user verified validation" do
    context "if user flags are off" do
      let(:assertion) { client.get(challenge: original_challenge, user_present: true, user_verified: false) }

      it "doesn't verify" do
        expect {
          assertion_response.verify(
            original_challenge,
            public_key: credential_public_key,
            sign_count: 0,
            user_verification: true
          )
        }.to raise_exception(WebAuthn::UserVerifiedVerificationError)
      end
    end
  end

  describe "challenge validation" do
    context "if challenge doesn't match" do
      it "doesn't verify" do
        expect {
          assertion_response.verify(fake_challenge, public_key: credential_public_key, sign_count: 0)
        }.to raise_exception(WebAuthn::ChallengeVerificationError)
      end

      it "is invalid" do
        expect(assertion_response.valid?(fake_challenge, public_key: credential_public_key, sign_count: 0)).to be_falsy
      end
    end
  end

  describe "origin validation" do
    context "if origin doesn't match" do
      let(:actual_origin) { "http://different-origin" }

      it "doesn't verify" do
        expect {
          assertion_response.verify(original_challenge, public_key: credential_public_key, sign_count: 0)
        }.to raise_exception(WebAuthn::OriginVerificationError)
      end

      it "is invalid" do
        expect(
          assertion_response.valid?(original_challenge, public_key: credential_public_key, sign_count: 0)
        ).to be_falsy
      end
    end
  end

  describe "tokenBinding validation" do
    let(:client) { WebAuthn::FakeClient.new(actual_origin, token_binding: token_binding, encoding: false) }

    context "it has stuff" do
      let(:token_binding) { { status: "supported" } }

      it "verifies" do
        expect(
          assertion_response.verify(original_challenge, public_key: credential_public_key, sign_count: 0)
        ).to be_truthy
      end

      it "is valid" do
        expect(
          assertion_response.valid?(original_challenge, public_key: credential_public_key, sign_count: 0)
        ).to be_truthy
      end
    end

    context "has an invalid format" do
      let(:token_binding) { "invalid token binding format" }

      it "doesn't verify" do
        expect {
          assertion_response.verify(original_challenge, public_key: credential_public_key, sign_count: 0)
        }.to raise_exception(WebAuthn::TokenBindingVerificationError)
      end

      it "isn't valid" do
        expect(
          assertion_response.valid?(original_challenge, public_key: credential_public_key, sign_count: 0)
        ).to be_falsy
      end
    end
  end

  describe "rp_id validation" do
    before do
      WebAuthn.configuration.rp_id = "different-rp_id"
    end

    context "if rp_id_hash doesn't match" do
      it "doesn't verify" do
        expect {
          assertion_response.verify(original_challenge, public_key: credential_public_key, sign_count: 0)
        }.to raise_exception(WebAuthn::RpIdVerificationError)
      end

      it "is invalid" do
        expect(
          assertion_response.valid?(original_challenge, public_key: credential_public_key, sign_count: 0)
        ).to be_falsy
      end
    end

    context "when correct rp_id is explicitly given" do
      it "verifies" do
        expect(
          assertion_response.verify(
            original_challenge,
            public_key: credential_public_key,
            sign_count: 0,
            rp_id: URI.parse(origin).host
          )
        ).to be_truthy
      end

      it "is valid" do
        expect(
          assertion_response.valid?(
            original_challenge,
            public_key: credential_public_key,
            sign_count: 0,
            rp_id: URI.parse(origin).host
          )
        ).to be_truthy
      end
    end
  end

  describe "sign_count validation" do
    context "if authenticator does not support counter" do
      let(:assertion) { client.get(challenge: original_challenge, sign_count: 0) }

      it "verifies" do
        expect(
          assertion_response.verify(original_challenge, public_key: credential_public_key, sign_count: 0)
        ).to be_truthy
      end
    end

    context "when the authenticator supports counter" do
      context "and it's greater than the stored counter" do
        let(:assertion) { client.get(challenge: original_challenge, sign_count: 6) }

        it "verifies" do
          expect(
            assertion_response.verify(original_challenge, public_key: credential_public_key, sign_count: 5)
          ).to be_truthy
        end
      end

      context "and it's equal to the stored counter" do
        let(:assertion) { client.get(challenge: original_challenge, sign_count: 5) }

        it "doesn't verify" do
          expect {
            assertion_response.verify(original_challenge, public_key: credential_public_key, sign_count: 5)
          }.to raise_exception(WebAuthn::SignCountVerificationError)
        end
      end

      context "and it's less than the stored counter" do
        let(:assertion) { client.get(challenge: original_challenge, sign_count: 4) }

        it "doesn't verify" do
          expect {
            assertion_response.verify(original_challenge, public_key: credential_public_key, sign_count: 5)
          }.to raise_exception(WebAuthn::SignCountVerificationError)
        end
      end

      context "when the RP opts out of verifying the signature counter" do
        let(:assertion) { client.get(challenge: original_challenge, sign_count: false) }

        it "verifies" do
          expect {
            assertion_response.verify(original_challenge, public_key: credential_public_key, sign_count: 5)
          }.to raise_exception(WebAuthn::SignCountVerificationError)
        end
      end
    end
  end

  describe "migrated U2F credential" do
    let(:origin) { "https://f69df4d9.ngrok.io" }
    let(:app_id) { "#{origin}/appid" }
    let(:migrated_credential) do
      WebAuthn::U2fMigrator.new(
        app_id: app_id,
        certificate: seeds[:u2f_migration][:stored_credential][:certificate],
        key_handle: seeds[:u2f_migration][:stored_credential][:key_handle],
        public_key: seeds[:u2f_migration][:stored_credential][:public_key],
        counter: 41
      )
    end
    let(:credential_public_key) { migrated_credential.credential.public_key }

    let(:assertion_data) { seeds[:u2f_migration][:assertion] }
    let(:assertion_response) do
      WebAuthn::AuthenticatorAssertionResponse.new(
        client_data_json: Base64.strict_decode64(assertion_data[:response][:client_data_json]),
        authenticator_data: Base64.strict_decode64(assertion_data[:response][:authenticator_data]),
        signature: Base64.strict_decode64(assertion_data[:response][:signature])
      )
    end
    let(:original_challenge) { Base64.strict_decode64(assertion_data[:challenge]) }

    context "when correct FIDO AppID is given as rp_id" do
      it "verifies" do
        expect(
          assertion_response.verify(original_challenge, public_key: credential_public_key, sign_count: 0, rp_id: app_id)
        ).to be_truthy
      end

      it "is valid" do
        expect(
          assertion_response.valid?(original_challenge, public_key: credential_public_key, sign_count: 0, rp_id: app_id)
        ).to be_truthy
      end
    end
  end

  context "when Authenticator Data is invalid" do
    let(:authenticator_data) { assertion["response"]["authenticatorData"][0..31] }

    it "doesn't verify" do
      expect {
        assertion_response.verify(original_challenge, public_key: credential_public_key, sign_count: 0)
      }.to raise_exception(WebAuthn::AuthenticatorDataVerificationError)
    end

    it "is invalid" do
      expect(
        assertion_response.valid?(original_challenge, public_key: credential_public_key, sign_count: 0)
      ).to be_falsy
    end
  end
end
