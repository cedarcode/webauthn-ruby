# frozen_string_literal: true

require "webauthn/public_key_credential/creation_options"
require "webauthn/public_key_credential/request_options"
require "webauthn/public_key_credential_with_assertion"
require "webauthn/public_key_credential_with_attestation"

module WebAuthn
  module Credential
    def self.create_options(options)
      WebAuthn::PublicKeyCredential::CreationOptions.new(options)
    end

    def self.get_options(options)
      WebAuthn::PublicKeyCredential::RequestOptions.new(options)
    end

    def self.from_create(credential)
      WebAuthn::PublicKeyCredentialWithAttestation.from_client(credential)
    end

    def self.from_get(credential)
      WebAuthn::PublicKeyCredentialWithAssertion.from_client(credential)
    end
  end
end
