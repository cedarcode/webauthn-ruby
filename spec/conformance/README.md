# FIDO2 conformance test server

This is a minimal server implementation for use with the FIDO2 Conformance Test Tool, which can be obtained after 
registration at https://fidoalliance.org/certification/functional-certification/conformance/

The code contained herein is _**not**_ representative of a production implementation of a WebAuthn relying party.

## Usage

Install dependencies using Bundler:
```
cd spec/conformance
bundle install
```

Start the server:
```
bundle exec ruby server.rb
```

Configure the FIDO2 Test Tool to use the following server URL: `http://localhost:4567` and run any of the server tests.
