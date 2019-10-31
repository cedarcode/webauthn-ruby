## Contributing to webauthn-ruby

### How?

- Creating a new issue to report a bug
- Creating a new issue to suggest a new feature
- Commenting on an existing issue to answer an open question
- Commenting on an existing issue to ask the reporter for more details to aid reproducing the problem
- Improving documentation
- Creating a pull request that fixes an issue (see [beginner friendly issues](https://github.com/cedarcode/webauthn-ruby/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22))
- Creating a pull request that implements a new feature (worth first creating an issue to discuss the suggested feature)

### Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake` to run the tests and code-style checks. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

Some tests require stubbing time with [libfaketime](https://github.com/wolfcw/libfaketime) in order to pass, otherwise they're skipped. You can install this library with your package manager. Follow libfaketime's instructions for your OS to preload the library before running the tests, and use the `FAKETIME_NO_CACHE=1` option. E.g. when installed via homebrew on macOS:
```shell
DYLD_INSERT_LIBRARIES=/usr/local/Cellar/libfaketime/2.9.7_1/lib/faketime/libfaketime.1.dylib DYLD_FORCE_FLAT_NAMESPACE=1 FAKETIME_NO_CACHE=1 bundle exec rspec
```

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

### Styleguide

#### Ruby

We use [rubocop](https://rubygems.org/gems/rubocop) to check ruby code style.

#### Git commit messages

We try to follow [Conventional Commits](https://conventionalcommits.org) specification since `v1.17.0`.

On top of `fix` and `feat` types, we also use optional:

* __build__: Changes that affect the build system or external dependencies
* __ci__: Changes to the CI configuration files and scripts
* __docs__: Documentation only changes
* __perf__: A code change that improves performance
* __refactor__: A code change that neither fixes a bug nor adds a feature
* __style__: Changes that do not affect the meaning of the code (white-space, formatting, missing semi-colons, etc)
* __test__: Adding missing tests or correcting existing tests

Partially inspired in [Angular's Commit Message Guidelines](https://github.com/angular/angular/blob/master/CONTRIBUTING.md#-commit-message-guidelines).
