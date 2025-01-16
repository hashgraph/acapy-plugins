# Hedera plugin

## Description

This plugin provides components for adding [Hedera DID method](https://github.com/hashgraph/did-method) and Anoncreds registry support for ACA-Py.

### Structure
Under the hood, the plugin consists from following core components:
- Hedera DID
  - HederaDIDResolver (implementation of [BaseDIDResolver](https://github.com/openwallet-foundation/acapy/blob/main/acapy_agent/resolver/base.py#L70) interface)
  - HederaDIDRegistrar (FIXME: we're currently using route handler manually)
- HederaAnonCredsRegistry (implementation of both [BaseAnonCredsResolver](https://github.com/openwallet-foundation/acapy/blob/main/acapy_agent/anoncreds/base.py#L109) and [BaseAnonCredsRegistrar](https://github.com/openwallet-foundation/acapy/blob/main/acapy_agent/anoncreds/base.py#L141) interfaces)

### API updates (TODO - double-check endpoints)

Hedera plugin aims to add Hedera DID support to existing ACA_Py flows, without bringing completely new functionality or API.

The plugin adds a new endpoint for creating Hedera DID:
- `POST /hedera/did/register`

Other operations with Hedera DID and Anoncreds registry supported via existing ACA-Py endpoints:
- `POST /anoncreds/schema`
- `POST /anoncreds/credential-definition`
- `POST /anoncreds/revocation/revoke`
- `GET /resolver/resolve/{did}`
- `GET /wallet/did`
- `GET /wallet/did/public`

## Demo

TODO

## Usage

### Prerequisites

- Python 3.10+
- JDK 21 - required for Hedera Python SDK which is a wrapper around Java SDK
  - Needs to be installed in a Docker container in order to run the plugin
  - The Temurin builds of [Eclipse Adoptium](https://adoptium.net/) are strongly recommended

### Configuration

- The plugin requires following Hedera-specific configuration to be provided:
  - Hedera network
    - High-level options from publicly available Hedera networks: "mainnet", "testnet" and "previewnet"
  - Hedera Operator configuration
    - Includes Hedera Operator ID and private key
    - Used for Hedera network integration and paying fees
- The plugin works only with `askar-anoncreds` wallet type

An example configuration for the plugin can be found in [plugins-config.yml](./docker/plugins-config.yml)

## Development

The best way to develop and manually test this plugin is to use the [Dev Container](https://containers.dev/) with configurations provided in the `.devcontainer` folder.
Recommended tool for running Dev Containers is [Visual Studio Code](https://code.visualstudio.com/).

- Make sure that Dev Container extension for VS Code is installed
- Open plugin folder in VS Code, see "open dev container" prompt and accept
- Dev container will be built, installing all necessary packages (plugin itself, supported ACA-Py version and other dependencies)
- Once container is ready, you can use `Run/Debug Plugin` configuration in VS code to run ACA-Py along with the plugin
  - You can use Swagger page at http://localhost:3001/api/doc#/ to manually test an API. However, using tools such as [Postman](https://www.postman.com/) is more convenient
  - Local ACA-Py instance is configured to use [multitenancy](https://aca-py.org/latest/features/Multitenancy/), so testing multiple agents and agent-to-agent integration is possible

## Unit tests

Unit tests are hosted under src folder: `hedera_did/tests`

Run tests using following command:
```bash
poetry run pytest
```
A coverage report is created when ran from the devcontainer. 

## Integration tests

Integration tests and configurations are hosted in `integration` folder.

See corresponding [README](./integration/README.md) for details.