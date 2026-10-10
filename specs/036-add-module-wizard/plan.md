# Implementation Plan: Add-Module Wizard (phase 3)

**Branch**: `036-add-module-wizard` | **Date**: 2026-10-10 | **Spec**: [spec.md](spec.md)

## Summary

Auth allows join tokens up to 24 h and reports whether a token was used. The
gateway gains `POST /ops/catalogue/{module}/join`: it checks host inputs,
ensures the allow-list entry, mints a token, renders the module's verified
bundle with core values, inputs and generated secrets, and returns a zip; a
join record drives a progress endpoint shown live in the console wizard.

## Technical Context

**Language/Version**: Go 1.26; Vue 3
**Primary Dependencies**: none new (stdlib `archive/zip`, `crypto/x509`)
**Storage**: gateway Postgres `catalogue_joins` (migration 0007); auth (no
schema change)
**Testing**: `go test -race`; auth bufconn tests; shell vitest
**Constraints**: no secrets persisted or logged; single round trip download

## Constitution Check

- [x] **I.** Default lifetime unchanged (10 min); 24 h only when asked; above max refused.
- [x] **II.** TokenStatus authorised for the gateway SPIFFE id only (auth policy).
- [x] **III.** Host inputs validated per declared pattern + SR-003; templates closed set.
- [x] **IV.** Tests first incl. negative: non-admin, bad inputs, prefix widening, allow-list conflict, auth down, unresolved placeholder, secrets absent from logs/audit.
- [x] **V.** `module_join_bundle` audit; refusals audited.
- [x] **VI.** No new dependency; stdlib crypto only (no custom primitives).
- [x] **VII.** Typed `catalogue.join` config.
- [x] **Threat Model**: research.md.

## Project Structure

```text
auth: go-tangra-auth (branch 036-add-module-wizard)
  internal/token/enroll.go (24 h, refuse above), api proto Enrollment.TokenStatus,
  internal/grpcapi (handler), deploy/policy.yaml (gateway may call TokenStatus)
portal: go-tangra-portal-v4 (branch 036-add-module-wizard, on top of 035)
  internal/store/migrations/0007_catalogue_joins.sql
  internal/catalogue/join.go      # inputs, render, secrets, zip
  internal/httpapi/catalogue_join.go
  internal/config (catalogue.join)
  shell: Add wizard (form, download, progress)
```
