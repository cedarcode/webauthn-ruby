# frozen_string_literal: true

require "spec_helper"
require "webauthn/fake_authenticator"
require "webauthn/fake_client"
require "webauthn/relying_party"

RSpec.describe "RelyingParty" do
  let(:credential_klass) { Struct.new(:webauthn_id, :public_key, :sign_count, keyword_init: true) }

  let(:authenticator) { WebAuthn::FakeAuthenticator.new }

  let(:admin_rp) do
    WebAuthn::RelyingParty.new(
      allowed_origins: ["https://admin.example.test"],
      id: 'admin.example.test',
      name: 'Admin Application'
    )
  end
  let(:admin_fake_client) do
    WebAuthn::FakeClient.new("https://admin.example.test", authenticator: authenticator)
  end

  let(:user) do
    user_klass = Struct.new(:id, :name, :credentials, keyword_init: true)
    user_klass.new(id: WebAuthn.generate_user_id, name: 'John Doe', credentials: [])
  end

  describe '#verify_registration' do
    let(:options) do
      admin_rp.options_for_registration(
        user: user.to_h.slice(:id, :name),
        exclude: user.credentials
      )
    end
    let(:raw_credential) do
      admin_fake_client.create(challenge: options.challenge, rp_id: admin_rp.id)
    end

    context "when user_presence" do
      let(:webauthn_credential_mock) { instance_double('WebAuthn::PublicKeyCredentialWithAttestation', verify: true) }

      before do
        allow(WebAuthn::Credential).to receive(:from_create).and_return(webauthn_credential_mock)
      end

      context "is not set" do
        it "correcly delegates its value to the response" do
          expect(webauthn_credential_mock).to receive(:verify).with(anything, hash_including(user_presence: nil))

          admin_rp.verify_registration(raw_credential, options.challenge)
        end
      end

      context "is set to false" do
        it "correcly delegates its value to the response" do
          expect(webauthn_credential_mock).to receive(:verify).with(anything, hash_including(user_presence: false))

          admin_rp.verify_registration(raw_credential, options.challenge, user_presence: false)
        end
      end

      context "is set to true" do
        it "correcly delegates its value to the response" do
          expect(webauthn_credential_mock).to receive(:verify).with(anything, hash_including(user_presence: true))

          admin_rp.verify_registration(raw_credential, options.challenge, user_presence: true)
        end
      end
    end
  end

  describe '#verify_authentication' do
    let(:options) { admin_rp.options_for_authentication(allow: user.credentials.map(&:webauthn_id)) }
    let(:raw_credential) { admin_fake_client.get(challenge: options.challenge, rp_id: admin_rp.id, sign_count: 1) }

    let(:admin_credential) { create_credential(client: admin_fake_client, relying_party: admin_rp) }
    let(:admin_credential_public_key) { admin_credential[1] }

    before do
      user.credentials << credential_klass.new(
        webauthn_id: admin_credential.first,
        public_key: admin_rp.encoder.encode(admin_credential[1]),
        sign_count: 0
      )
    end

    context "when user_presence" do
      let(:webauthn_credential_mock) { instance_double('WebAuthn::PublicKeyCredentialWithAssertion', verify: true) }

      before do
        allow(WebAuthn::Credential).to receive(:from_get).and_return(webauthn_credential_mock)
      end

      context "is not set" do
        it "correcly delegates its value to the response" do
          expect(webauthn_credential_mock).to receive(:verify).with(anything, hash_including(user_presence: nil))

          admin_rp.verify_authentication(
            raw_credential,
            options.challenge,
            public_key: admin_credential_public_key,
            sign_count: 0
          )
        end
      end

      context "is set to false" do
        it "correcly delegates its value to the response" do
          expect(webauthn_credential_mock).to receive(:verify).with(anything, hash_including(user_presence: false))

          admin_rp.verify_authentication(
            raw_credential,
            options.challenge,
            public_key: admin_credential_public_key,
            sign_count: 0,
            user_presence: false
          )
        end
      end

      context "is set to true" do
        it "correcly delegates its value to the response" do
          expect(webauthn_credential_mock).to receive(:verify).with(anything, hash_including(user_presence: true))

          admin_rp.verify_authentication(
            raw_credential,
            options.challenge,
            public_key: admin_credential_public_key,
            sign_count: 0,
            user_presence: true
          )
        end
      end
    end
  end

  describe '#origin' do
    subject do
      old_verbose, $VERBOSE = $VERBOSE, nil # Silence warnings to avoid deprecation warnings

      rp.origin
    ensure
      $VERBOSE = old_verbose
    end

    context 'when relying party has only one allowed origin' do
      let(:rp) do
        WebAuthn::RelyingParty.new(allowed_origins: ["https://admin.example.test"])
      end

      it 'returns that allowed origin' do
        is_expected.to eq("https://admin.example.test")
      end
    end

    context 'when relying party has multiple allowed origins' do
      let(:rp) do
        WebAuthn::RelyingParty.new(allowed_origins: ["https://admin.example.test", "https://newadmin.example.test"])
      end

      it { is_expected.to be_nil }
    end

    context 'when relying party has not set its allowed origins' do
      let(:rp) do
        WebAuthn::RelyingParty.new(allowed_origins: nil)
      end

      it { is_expected.to be_nil }
    end
  end

  context "without having any global configuration" do
    let(:consumer_rp) do
      WebAuthn::RelyingParty.new(
        allowed_origins: ["https://www.example.test"],
        id: 'example.test',
        name: 'Consumer Application'
      )
    end
    let(:consumer_fake_client) do
      WebAuthn::FakeClient.new("https://www.example.test", authenticator: authenticator)
    end

    context "instance two relying parties and use them for the registration ceremony" do
      it "works when both used for the same user and authenticator" do
        options = admin_rp.options_for_registration(
          user: user.to_h.slice(:id, :name),
          exclude: user.credentials
        )
        raw_credential = admin_fake_client.create(challenge: options.challenge, rp_id: admin_rp.id)
        webauthn_credential = admin_rp.verify_registration(raw_credential, options.challenge)

        expect(webauthn_credential).to be_truthy
        expect(webauthn_credential.id).to be_truthy
        expect(webauthn_credential.public_key).to be_truthy
        expect(webauthn_credential.sign_count).to eq(0)

        options = consumer_rp.options_for_registration(
          user: user.to_h.slice(:id, :name),
          exclude: user.credentials
        )
        raw_credential = consumer_fake_client.create(challenge: options.challenge, rp_id: consumer_rp.id)
        webauthn_credential = consumer_rp.verify_registration(raw_credential, options.challenge)

        expect(webauthn_credential).to be_truthy
        expect(webauthn_credential.id).to be_truthy
        expect(webauthn_credential.public_key).to be_truthy
        expect(webauthn_credential.sign_count).to eq(0)
      end

      it "fails if you pass consumer client data to admin relying party" do
        options = admin_rp.options_for_registration(
          user: user.to_h.slice(:id, :name),
          exclude: user.credentials
        )
        raw_credential = consumer_fake_client.create(challenge: options.challenge)

        expect do
          admin_rp.verify_registration(raw_credential, options.challenge)
        end.to raise_error(WebAuthn::OriginVerificationError)
      end
    end

    context "configuring relying parties and use them for the authentication ceremony" do
      let(:admin_credential) do
        create_credential(client: admin_fake_client, relying_party: admin_rp)
      end
      let(:consumer_credential) do
        create_credential(client: consumer_fake_client, relying_party: consumer_rp)
      end

      before do
        user.credentials << credential_klass.new(
          webauthn_id: admin_credential.first,
          public_key: admin_rp.encoder.encode(admin_credential[1]),
          sign_count: 0
        )
        user.credentials << credential_klass.new(
          webauthn_id: consumer_credential.first,
          public_key: consumer_rp.encoder.encode(consumer_credential[1]),
          sign_count: 0
        )
      end

      it "works when both used for the same user and authenticator" do
        options = admin_rp.options_for_authentication(allow: user.credentials.map(&:webauthn_id))

        raw_credential = admin_fake_client.get(
          challenge: options.challenge,
          rp_id: admin_rp.id,
          sign_count: 1
        )

        verified_webauthn_credential, stored_credential =
          admin_rp.verify_authentication(
            raw_credential,
            options.challenge
          ) do |webauthn_credential|
          user.credentials.find { |c| c.webauthn_id == webauthn_credential.id }
        end

        expect(verified_webauthn_credential).to be_truthy
        expect(verified_webauthn_credential.id).to be_truthy
        expect(verified_webauthn_credential.sign_count).to eq(1)
        expect(stored_credential.webauthn_id).to eq(admin_credential.first)

        options = consumer_rp.options_for_authentication(allow: user.credentials.map(&:webauthn_id))

        raw_credential = consumer_fake_client.get(
          challenge: options.challenge,
          rp_id: consumer_rp.id,
          sign_count: 1
        )

        verified_webauthn_credential, stored_credential =
          consumer_rp.verify_authentication(
            raw_credential,
            options.challenge
          ) do |webauthn_credential|
          user.credentials.find { |c| c.webauthn_id == webauthn_credential.id }
        end

        expect(verified_webauthn_credential).to be_truthy
        expect(verified_webauthn_credential.id).to be_truthy
        expect(verified_webauthn_credential.sign_count).to eq(1)
        expect(stored_credential.webauthn_id).to eq(consumer_credential.first)
      end

      it "fails when you try to authenticate a credential registered for consumer in admin" do
        options = admin_rp.options_for_authentication(allow: user.credentials.map(&:webauthn_id))

        raw_credential = admin_fake_client.get(
          challenge: options.challenge,
          rp_id: admin_rp.id,
          sign_count: 1
        )

        expect do
          admin_rp.verify_authentication(
            raw_credential,
            options.challenge
          ) do
            user.credentials.find { |c| c.webauthn_id == consumer_credential.first }
          end
        end.to raise_error(WebAuthn::SignatureVerificationError)
      end
    end
  end

  context "with a global configuration and a different relying party co-existing" do
    let(:global_configuration_client) do
      WebAuthn::FakeClient.new(WebAuthn.configuration.allowed_origins[0], authenticator: authenticator)
    end

    before do
      WebAuthn.configure do |config|
        config.allowed_origins = ["https://www.example.com"]
        config.rp_name = "Example Consumer page"
      end
    end

    context "when performing a registragion ceremony" do
      it "works when both used for the same user and authenticator" do
        options = admin_rp.options_for_registration(
          user: user.to_h.slice(:id, :name),
          exclude: user.credentials
        )
        raw_credential = admin_fake_client.create(challenge: options.challenge, rp_id: admin_rp.id)
        webauthn_credential = admin_rp.verify_registration(raw_credential, options.challenge)

        expect(webauthn_credential).to be_truthy
        expect(webauthn_credential.id).to be_truthy
        expect(webauthn_credential.public_key).to be_truthy
        expect(webauthn_credential.sign_count).to eq(0)

        options = WebAuthn.configuration.relying_party.options_for_registration(
          user: user.to_h.slice(:id, :name),
          exclude: user.credentials
        )
        raw_credential = global_configuration_client.create(challenge: options.challenge)
        webauthn_credential =
          WebAuthn.configuration.relying_party.verify_registration(
            raw_credential,
            options.challenge
          )

        expect(webauthn_credential).to be_truthy
        expect(webauthn_credential.id).to be_truthy
        expect(webauthn_credential.public_key).to be_truthy
        expect(webauthn_credential.sign_count).to eq(0)
      end
    end

    context "when performing an authentication ceremony" do
      let(:admin_credential) do
        create_credential(client: admin_fake_client, relying_party: admin_rp)
      end
      let(:default_configuration_credential) do
        create_credential(client: global_configuration_client)
      end

      before do
        user.credentials << credential_klass.new(
          webauthn_id: admin_credential.first,
          public_key: admin_rp.encoder.encode(admin_credential[1]),
          sign_count: 0
        )
        user.credentials << credential_klass.new(
          webauthn_id: default_configuration_credential.first,
          public_key: WebAuthn.configuration.encoder.encode(default_configuration_credential[1]),
          sign_count: 0
        )
      end

      it "works when both used for the same user and authenticator" do
        options = admin_rp.options_for_authentication(allow: user.credentials.map(&:webauthn_id))

        raw_credential = admin_fake_client.get(
          challenge: options.challenge,
          rp_id: admin_rp.id,
          sign_count: 1
        )

        verified_webauthn_credential, stored_credential =
          admin_rp.verify_authentication(
            raw_credential,
            options.challenge
          ) do |webauthn_credential|
          user.credentials.find { |c| c.webauthn_id == webauthn_credential.id }
        end

        expect(verified_webauthn_credential).to be_truthy
        expect(verified_webauthn_credential.id).to be_truthy
        expect(verified_webauthn_credential.sign_count).to eq(1)
        expect(stored_credential.webauthn_id).to eq(admin_credential.first)

        options =
          WebAuthn.configuration.relying_party.options_for_authentication(
            allow: user.credentials.map(&:webauthn_id)
          )

        raw_credential = global_configuration_client.get(
          challenge: options.challenge,
          sign_count: 1
        )

        verified_webauthn_credential, stored_credential =
          WebAuthn.configuration.relying_party.verify_authentication(
            raw_credential,
            options.challenge
          ) do |webauthn_credential|
          user.credentials.find { |c| c.webauthn_id == webauthn_credential.id }
        end

        expect(verified_webauthn_credential).to be_truthy
        expect(verified_webauthn_credential.id).to be_truthy
        expect(verified_webauthn_credential.sign_count).to eq(1)
        expect(stored_credential.webauthn_id).to eq(default_configuration_credential.first)
      end
    end
  end

  context "with only a global configuration" do
    let(:global_configuration_client) do
      WebAuthn::FakeClient.new(WebAuthn.configuration.allowed_origins[0], authenticator: authenticator)
    end

    before do
      WebAuthn.configure do |config|
        config.allowed_origins = ["https://www.example.com"]
        config.rp_name = "Example Consumer page"
      end
    end

    context "when performing a registragion ceremony" do
      it "works well when using the former interface" do
        options = WebAuthn::Credential.options_for_create(
          user: user.to_h.slice(:id, :name),
          exclude: user.credentials
        )
        raw_credential = global_configuration_client.create(challenge: options.challenge)
        webauthn_credential = WebAuthn::Credential.from_create(raw_credential)
        webauthn_credential.verify(options.challenge)

        expect(webauthn_credential).to be_truthy
        expect(webauthn_credential.id).to be_truthy
        expect(webauthn_credential.public_key).to be_truthy
        expect(webauthn_credential.sign_count).to eq(0)
      end
    end

    context "when performing an authentication ceremony" do
      let(:default_configuration_credential) do
        create_credential(client: global_configuration_client)
      end

      before do
        user.credentials << credential_klass.new(
          webauthn_id: default_configuration_credential.first,
          public_key: WebAuthn.configuration.encoder.encode(default_configuration_credential[1]),
          sign_count: 0
        )
      end

      it "works well when using the former interface" do
        options = WebAuthn::Credential.options_for_get(allow: user.credentials.map(&:webauthn_id))

        raw_credential = global_configuration_client.get(
          challenge: options.challenge,
          sign_count: 1
        )

        webauthn_credential = WebAuthn::Credential.from_get(raw_credential)
        stored_credential = user.credentials.find { |c| c.webauthn_id == webauthn_credential.id }
        webauthn_credential.verify(
          options.challenge,
          public_key: stored_credential.public_key,
          sign_count: stored_credential.sign_count
        )

        expect(webauthn_credential).to be_truthy
        expect(webauthn_credential.id).to be_truthy
        expect(webauthn_credential.sign_count).to eq(1)
      end
    end
  end
end
