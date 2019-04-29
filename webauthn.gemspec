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
    Relying Party and allow your users to authenticate with U2F and FIDO 2.0 authenticators.'
  spec.homepage      = "https://github.com/cedarcode/webauthn-ruby"
  spec.license       = "MIT"

  spec.metadata = {
    "bug_tracker_uri" => "https://github.com/cedarcode/webauthn-ruby/issues",
    "changelog_uri" => "https://github.com/cedarcode/webauthn-ruby/blob/master/CHANGELOG.md",
    "source_code_uri" => "https://github.com/cedarcode/webauthn-ruby"
  }

  spec.files = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.required_ruby_version = ">= 2.3"

  spec.add_dependency "bindata", "~> 2.4"
  spec.add_dependency "cbor", "~> 0.5.9"
  spec.add_dependency "cose", "~> 0.6.0"
  spec.add_dependency "jwt", [">= 1.5", "< 3.0"]
  spec.add_dependency "openssl", "~> 2.0"
  spec.add_dependency "securecompare", "~> 1.0"

  spec.add_development_dependency "appraisal", "~> 2.2.0"
  spec.add_development_dependency "bundler", ">= 1.17", "< 3.0"
  spec.add_development_dependency "byebug", "~> 11.0"
  spec.add_development_dependency "rake", "~> 12.3"
  spec.add_development_dependency "rspec", "~> 3.8"
  spec.add_development_dependency "rubocop", "0.67.2"
end
