# AIRLOCK Security Lab Repository (Synthetic Test Environment)

This is a dedicated, disposable demonstration repository managed under AIRLOCK's Zero-Trust AI Security Gateway.

## Architecture

- **Security Boundary**: All AI agent access is mediated through AIRLOCK.
- **Protected Branch**: `main` (Direct write or force-push prohibited).
- **Test Branch**: `feature/update` (Subject to Human-in-the-Loop approval).
- **Classification**: Internal Synthetic Lab (No production secrets or real user data).

## Features

- Zero-Trust MCP tool enforcement
- Prompt injection containment
- Credential leak detection (DLP)
- Policy-governed Pull Request workflows
