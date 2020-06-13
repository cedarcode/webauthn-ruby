# frozen_string_literal: true

require "bundler/setup"
require "webauthn"
require "cbor"

require "byebug"
require "webauthn/fake_client"

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end

  config.after do
    WebAuthn.instance_variable_set(:@configuration, nil)
  end
end

def create_credential(
  client: WebAuthn::FakeClient.new,
  rp_id: nil,
  relying_party: WebAuthn.configuration.relying_party
)
  rp_id ||= relying_party.id || URI.parse(client.origin).host

  create_result = client.create(rp_id: rp_id)

  attestation_object = if client.encoding
    relying_party.encoder.decode(create_result["response"]["attestationObject"])
  else
    create_result["response"]["attestationObject"]
  end

  client_data_json = if client.encoding
    relying_party.encoder.decode(create_result["response"]["clientDataJSON"])
  else
    create_result["response"]["clientDataJSON"]
  end

  credential_public_key =
    WebAuthn::AuthenticatorAttestationResponse
    .new(
      attestation_object: attestation_object,
      client_data_json: client_data_json,
      relying_party: relying_party
    )
    .credential
    .public_key

  [create_result["id"], credential_public_key]
end

def fake_origin
  "http://localhost"
end

def fake_challenge
  SecureRandom.random_bytes(32)
end

def fake_cose_credential_key(algorithm: -7, x_coordinate: nil, y_coordinate: nil)
  crv_p256 = 1

  COSE::Key::EC2.new(
    alg: algorithm,
    crv: crv_p256,
    x: x_coordinate || SecureRandom.random_bytes(32),
    y: y_coordinate || SecureRandom.random_bytes(32)
  ).serialize
end

def key_bytes(public_key)
  public_key.to_bn.to_s(2)
end

# Borrowed from activesupport
def silence_warnings
  old_verbose, $VERBOSE = $VERBOSE, nil
  yield
ensure
  $VERBOSE = old_verbose
end

class RootCertificateFinder
  def initialize(certificate, return_empty)
    @certificate = certificate
    @return_empty = return_empty
  end

  def find(*)
    if @return_empty
      []
    elsif @certificate.is_a?(OpenSSL::X509::Certificate)
      [@certificate]
    else
      certificate_path = File.expand_path(
        File.join(__dir__, 'support', 'roots', @certificate)
      )
      [OpenSSL::X509::Certificate.new(File.read(certificate_path))]
    end
  end
end

def finder_for(certificate_file, return_empty: false)
  RootCertificateFinder.new(certificate_file, return_empty)
end

def create_rsa_key
  key_bits = 1024 # NOTE: Use 2048 or more in real life! We use 1024 here just for making the test fast.

  OpenSSL::PKey::RSA.new(key_bits)
end

def create_root_certificate(key)
  certificate = OpenSSL::X509::Certificate.new
  common_name = "Root-#{rand(1_000_000)}"

  certificate.subject = OpenSSL::X509::Name.new([["CN", common_name]])
  certificate.issuer = certificate.subject
  certificate.public_key = root_key
  certificate.not_before = Time.now - 1
  certificate.not_after = Time.now + 60

  extension_factory = OpenSSL::X509::ExtensionFactory.new
  extension_factory.subject_certificate = certificate
  extension_factory.issuer_certificate = certificate

  certificate.extensions = [
    extension_factory.create_extension("basicConstraints", "CA:TRUE", true),
    extension_factory.create_extension("keyUsage", "keyCertSign,cRLSign", true),
  ]

  certificate.sign(key, OpenSSL::Digest::SHA256.new)

  certificate
end

def issue_certificate(ca_certificate, ca_key, key, name: nil)
  certificate = OpenSSL::X509::Certificate.new
  common_name = name || "Cert-#{rand(1_000_000)}"

  certificate.subject = OpenSSL::X509::Name.new([["CN", common_name]])
  certificate.issuer = ca_certificate.subject
  certificate.not_before = Time.now - 1
  certificate.not_after = Time.now + 60
  certificate.public_key = key

  certificate.sign(ca_key, OpenSSL::Digest::SHA256.new)

  certificate
end
