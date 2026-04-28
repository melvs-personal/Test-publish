# Shared Action Repo Template

Use this folder as the source for a standalone shared action repository.

## 1. Create centralized repository

Create a new repository, for example:

- `your-org/secure-http-header-check-action`

Copy these files from this template folder into that repository root:

- `action.yml`
- `validate-headers.js`
- `.github/workflows/release-tag.yml`

## 2. Create initial version tags

Run the `Release Shared Action Tag` workflow with `version=v1.0.0`.

That workflow creates:

- `v1.0.0` immutable release tag
- `v1` moving major tag

## 3. Reference from all repositories by tag

In consuming repositories, use:

```yaml
- name: Validate secure headers
  id: header_check
  uses: your-org/secure-http-header-check-action@v1
  with:
    urls: ${{ vars.SECURE_HEADER_URLS }}
    timeout-seconds: 15
    compliance-profile: jobaid
    custom-required-headers: '{"cross-origin-opener-policy":"same-origin"}'
```

Available compliance profiles:

- `default`: current baseline secure header checks
- `jobaid` or `accenture-jobaid`: baseline checks plus cross-origin isolation checks
  - `Cross-Origin-Opener-Policy: same-origin`
  - `Cross-Origin-Resource-Policy: same-origin` or `same-site`
  - `Cross-Origin-Embedder-Policy: require-corp`

## 4. Upload SARIF in consuming workflows

```yaml
- name: Upload SARIF
  if: always() && steps.header_check.outputs.sarif-file != ''
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.header_check.outputs.sarif-file }}
    category: secure-http-header-check
```

Set workflow permissions in consumers:

```yaml
permissions:
  contents: read
  security-events: write
```
Check Jira