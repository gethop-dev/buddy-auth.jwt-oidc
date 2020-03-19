# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

## [UNRELEASED]

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

[UNRELEASED]:  https://github.com/magnetcoop/buddy-auth.jwt-oidc/compare/v0.8.3...HEAD
[0.8.3]: https://github.com/magnetcoop/buddy-auth.jwt-oidc/compare/v0.8.3...v0.8.2
[0.8.2]: https://github.com/magnetcoop/buddy-auth.jwt-oidc/compare/v0.8.2...v0.8.1
[0.8.1]: https://github.com/magnetcoop/buddy-auth.jwt-oidc/compare/v0.8.1...v0.8.0
[0.8.0]: https://github.com/magnetcoop/buddy-auth.jwt-oidc/compare/v0.8.0...v0.7.0
[0.7.0]: https://github.com/magnetcoop/buddy-auth.jwt-oidc/compare/v0.7.0...v0.6.0
[0.6.0]: https://github.com/magnetcoop/buddy-auth.jwt-oidc/compare/v0.6.0...v0.5.0
[0.5.0]: https://github.com/magnetcoop/buddy-auth.jwt-oidc/compare/v0.5.0...v0.4.0
[0.4.0]: https://github.com/magnetcoop/buddy-auth.jwt-oidc/compare/v0.4.0...v0.3.0
[0.3.0]: https://github.com/magnetcoop/buddy-auth.jwt-oidc/releases/tag/v0.3.0

