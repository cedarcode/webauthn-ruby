# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "webauthn/version"

Gem::Specification.new do |spec|
  spec.name          = "webauthn"
  spec.version       = WebAuthn::VERSION
  spec.authors       = ["Gonzalo Rodriguez", "Braulio Martinez"]
  spec.email         = ["gonzalo@cedarcode.com", "braulio@cedarcode.com"]

  spec.summary       = "WebAuthn ruby server library"
  spec.description   = 'WebAuthn ruby server library ― Make your application a W3C Web Authentication conformant
    Relying Party and allow your users to authenticate with U2F and FIDO2 authenticators.'
  spec.homepage      = "https://github.com/cedarcode/webauthn-ruby"
  spec.license       = "MIT"

  spec.metadata = {
    "bug_tracker_uri" => "https://github.com/cedarcode/webauthn-ruby/issues",
    "changelog_uri" => "https://github.com/cedarcode/webauthn-ruby/blob/master/CHANGELOG.md",
    "source_code_uri" => "https://github.com/cedarcode/webauthn-ruby"
  }

  spec.files =
    `git ls-files -z`.split("\x0").reject do |f|
      f.match(%r{^(test|spec|features|assets)/})
    end

  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.required_ruby_version = ">= 2.5"

  spec.add_dependency "android_key_attestation", "~> 0.3.0"
  spec.add_dependency "awrence", "~> 1.1"
  spec.add_dependency "bindata", "~> 2.4"
  spec.add_dependency "cbor", "~> 0.5.9"
  spec.add_dependency "cose", "~> 1.1"
  spec.add_dependency "openssl", ">= 2.2"
  spec.add_dependency "safety_net_attestation", "~> 0.4.0"
  spec.add_dependency "tpm-key_attestation", "~> 0.12.0"

  spec.add_development_dependency "base64", ">= 0.1.0"
  spec.add_development_dependency "bundler", ">= 1.17", "< 3.0"
  spec.add_development_dependency "byebug", "~> 11.0"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rspec", "~> 3.8"
  spec.add_development_dependency "rubocop", "~> 1.9.1"
  spec.add_development_dependency "rubocop-rake", "~> 0.5.1"
  spec.add_development_dependency "rubocop-rspec", "~> 2.2.0"
end
