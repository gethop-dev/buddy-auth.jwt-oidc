# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

## [UNRELEASED]

### Changed
- Upgraded clj-kondo version.
- Tweaked the clj-kondo configuration to deal with the newer `unresolved-var` linter.
- Let git ignore all third party libraries clj-kondo configuration files.
- Added JVM options to let AWS SDK call some JAVA 9+ internal methods (development only).
- Remove unused vars in the test namespace.

## [0.10.6] - 2023-02-19

### Changed
- Internal implementation details. Merged validate-single-key into validate-token* and changed the way the pubkeys from JWKS are stored in the cache. It avoids looping over pubkeys that, while valid, will not unsign the token (because it has been signed by another valid key from the same key set). And logging their corresponding failures.

## [0.10.5] - 2023-02-13

### Changed
- Making `create-token` and `now-in-secs` test functions public
- Split args in `create-token` test function to separate claims and key signing details
- Bumped dependencies

## [0.10.4] - 2022-05-25

### Changed
- Moving the repository to [gethop-dev](https://github.com/gethop-dev) organization
- CI/CD solution switch from [TravisCI](https://travis-ci.org/) to [GitHub Actions](Ihttps://github.com/features/actions)
- `lein`, `cljfmt` and `eastwood` dependencies bump
- More `clj-kondo` linters config
- update this changelog's releases tags links

## [0.10.3] - 2021-05-07

### Changed
- Use our own forked versin of per item TTL cache. It fixes a nasty bug that was making evicted entries look like they were alive in the cache, but returning a nil value when looked up.

## [0.10.2] - 2021-03-31

### Added
- More debugging information, for other corner cases.

## [0.10.1] - 2021-03-30

### Added
- Lots of additional debugging information to be able to diagnose corner cases.

## [0.10.0] - 2020-10-29

### Changed
- **[BREAKING CHANGE]** Upgraded http-kit dependency to 2.5.0. This change bumps the minimum JVM version from 1.6 to 1.7!

## [0.9.0] - 2020-08-24

### Changed
- Upgraded http-kit dependency to 2.4.0. This fixes issue #1.

## [0.8.6] - 2020-07-01

### Changed
- Explicitly prevent verifying tokens with the 'none' algorithm (instead of relying on the behaviour of the underlying JWT library).

## [0.8.5] - 2020-03-19

### Fixed
- Emergency fix for last minute non-tested change that breaks the build.

## [0.8.4] - 2020-03-19

### Changed
- Upgraded dependencies

### Added
- You can now provide two additional configuration keys for JWKS retrieval connection policy. `:jwks-retrieval-timeout` specifies the connection timeout (in milli-seconds) and `:jwks-retrieval-retries` specifies the number of additional retries in case of connection failure.

## [0.8.3] - 2020-03-02

### Changed
- Bumped Amazonica dependency version (devel profile only)
- Removed CIDER dependency (devel profile only)
- Bumped mininum Leiningen version to 2.9.0.
- Reorganized dev profile definition to allow to override some settings via profiles.clj file inside project's directory.
- Increased timeout to 500s with 3 max retries (from 250ms with 5 max retries)

### Added
- Made a couple of caching related unit test more thorough, to make sure we do the right thing.

## [0.7.0] - 2019-09-06

### Changed
- 'aud' claim can now be either a single string value or a collection of them. The aud claim of the token is checked against all of them.

## [0.6.0] - 2019-06-18

### Changed
- Fixed installation instructions in README.md

### Added
- This CHANGELOG
- Implemented JWKS keys retrieval retries with [diehard](https://github.com/sunng87/diehard)
- You can now provide a configuration key that implements the `duct.logger/Logger` protocol and the the library will log any relevant issues that may prevent tokens from being validated (e.g., inability to get the JWKS URL, getting invalid keys in the JWKS body, etc.)

## [0.5.0] - 2019-02-21

### Changed
- Added composed cache to set token storage limit. This was previously disabled (even if it was documented as working in the README), as composition with `ttlcache` didn't seem to work.
- Bumped CIDER version dependency (devel profile only)

## [0.4.0] - 2019-01-29

### Added
- Updated Clojure version to 1.10.0
- Added deploy config

## [0.3.0] - 2019-01-28
- Initial commit (previous versions were not publicly released)

[UNRELEASED]:  https://github.com/gethop-dev/buddy-auth.jwt-oidc/compare/v0.10.6...HEAD
[0.10.6]: https://github.com/gethop-dev/buddy-auth.jwt-oidc/releases/tag/v0.10.6
[0.10.5]: https://github.com/gethop-dev/buddy-auth.jwt-oidc/releases/tag/v0.10.5
[0.10.4]: https://github.com/gethop-dev/buddy-auth.jwt-oidc/releases/tag/v0.10.4
[0.10.3]: https://github.com/gethop-dev/buddy-auth.jwt-oidc/releases/tag/v0.10.3
[0.10.2]: https://github.com/gethop-dev/buddy-auth.jwt-oidc/releases/tag/v0.10.2
[0.10.1]: https://github.com/gethop-dev/buddy-auth.jwt-oidc/releases/tag/v0.10.1
[0.10.0]: https://github.com/gethop-dev/buddy-auth.jwt-oidc/releases/tag/v0.10.0
[0.9.0]: https://github.com/gethop-dev/buddy-auth.jwt-oidc/releases/tag/v0.9.0
[0.8.6]: https://github.com/gethop-dev/buddy-auth.jwt-oidc/releases/tag/0.8.6
[0.8.5]: https://github.com/gethop-dev/buddy-auth.jwt-oidc/releases/tag/0.8.5
[0.8.4]: https://github.com/gethop-dev/buddy-auth.jwt-oidc/releases/tag/0.8.4
[0.8.3]: https://github.com/gethop-dev/buddy-auth.jwt-oidc/releases/tag/0.8.3
[0.8.2]: https://github.com/gethop-dev/buddy-auth.jwt-oidc/releases/tag/0.8.2
[0.8.1]: https://github.com/gethop-dev/buddy-auth.jwt-oidc/releases/tag/0.8.1
[0.8.0]: https://github.com/gethop-dev/buddy-auth.jwt-oidc/releases/tag/0.8.0
[0.7.0]: https://github.com/gethop-dev/buddy-auth.jwt-oidc/releases/tag/0.7.0
[0.6.0]: https://github.com/gethop-dev/buddy-auth.jwt-oidc/releases/tag/0.6.0
[0.5.0]: https://github.com/gethop-dev/buddy-auth.jwt-oidc/releases/tag/0.5.0
[0.4.0]: https://github.com/gethop-dev/buddy-auth.jwt-oidc/releases/tag/v0.4.0
[0.3.0]: https://github.com/gethop-dev/buddy-auth.jwt-oidc/releases/tag/v0.3.0
