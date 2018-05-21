lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "webauthn/version"

Gem::Specification.new do |spec|
  spec.name          = "webauthn"
  spec.version       = WebAuthn::VERSION
  spec.authors       = ["Gonzalo Rodriguez"]
  spec.email         = ["gonzalo@cedarcode.com"]

  spec.summary       = %q{Web Authentication API Relying Party in ruby}
  spec.homepage      = "https://github.com/cedarcode/webauthn-ruby"
  spec.license       = "MIT"

  spec.metadata = {
    "bug_tracker_uri" => "https://github.com/cedarcode/webauthn-ruby/issues",
    "changelog_uri" => "https://github.com/cedarcode/webauthn-ruby/blob/master/CHANGELOG.md",
    "source_code_uri" => "https://github.com/cedarcode/webauthn-ruby"
  }

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "cbor", "~> 0.5.9.2"

  spec.add_development_dependency "bundler", "~> 1.16"
  spec.add_development_dependency "byebug", "~> 10.0"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
end
