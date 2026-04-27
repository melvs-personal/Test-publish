#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const DEFAULT_TIMEOUT_SECONDS = 15;
const DEFAULT_SARIF_FILE = 'secure-http-header-check.sarif';
const DEFAULT_COMPLIANCE_PROFILE = 'default';

function splitUrls(raw) {
  return String(raw || '')
    .split(/[\n,]/)
    .map((v) => v.trim())
    .filter(Boolean);
}

function parseInteger(raw, fallback) {
  const n = Number(raw);
  if (!Number.isInteger(n) || n <= 0) return fallback;
  return n;
}

function normaliseHeaderMap(headers) {
  const out = {};
  for (const [name, value] of headers.entries()) {
    out[name.toLowerCase()] = value;
  }
  return out;
}

function appendOutput(name, value) {
  const outputPath = process.env.GITHUB_OUTPUT;
  if (!outputPath) return;
  fs.appendFileSync(outputPath, `${name}=${value}\n`, 'utf8');
}

function appendSummary(lines) {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (!summaryPath) return;
  fs.appendFileSync(summaryPath, `${lines.join('\n')}\n`, 'utf8');
}

function escapeAnnotationValue(value) {
  return String(value)
    .replace(/%/g, '%25')
    .replace(/\r/g, '%0D')
    .replace(/\n/g, '%0A');
}

function emitErrorAnnotation(violation) {
  const title = escapeAnnotationValue(`Secure Header Check: ${violation.header}`);
  const message = escapeAnnotationValue(`${violation.url} -> ${violation.message}`);
  console.log(`::error title=${title}::${message}`);
}

function toRuleId(violation) {
  const normalized = `${violation.header || 'runtime'}-${violation.message || 'violation'}`
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return normalized || 'secure-http-header-violation';
}

function buildSarif(violations) {
  const rules = [];
  const seen = new Set();

  for (const v of violations) {
    const ruleId = toRuleId(v);
    if (seen.has(ruleId)) continue;
    seen.add(ruleId);
    rules.push({
      id: ruleId,
      name: v.header || 'runtime',
      shortDescription: {
        text: `Secure HTTP header validation for ${v.header || 'runtime'}`,
      },
      help: {
        text: v.message,
      },
      properties: {
        category: 'security',
      },
    });
  }

  const results = violations.map((v) => ({
    ruleId: toRuleId(v),
    level: 'error',
    message: {
      text: `${v.message}${v.actual ? ` (actual: ${v.actual})` : ''}`,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: v.url,
          },
        },
      },
    ],
    properties: {
      url: v.url,
      header: v.header,
    },
  }));

  return {
    version: '2.1.0',
    $schema: 'https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'secure-http-header-check',
            version: '1.0.0',
            informationUri: 'https://github.com',
            rules,
          },
        },
        results,
      },
    ],
  };
}

function resolveSarifPath(inputPath) {
  if (inputPath && inputPath.trim()) {
    return path.resolve(inputPath.trim());
  }

  const runnerTemp = process.env.RUNNER_TEMP;
  if (runnerTemp && runnerTemp.trim()) {
    return path.resolve(runnerTemp, DEFAULT_SARIF_FILE);
  }

  return path.resolve(process.cwd(), DEFAULT_SARIF_FILE);
}

function writeSarifFile(sarifPath, violations) {
  const directory = path.dirname(sarifPath);
  fs.mkdirSync(directory, { recursive: true });
  const sarif = buildSarif(violations);
  fs.writeFileSync(sarifPath, JSON.stringify(sarif, null, 2), 'utf8');
}

function isValidUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

async function fetchWithTimeout(url, method, timeoutSeconds) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutSeconds * 1000);

  try {
    return await fetch(url, {
      method,
      redirect: 'follow',
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timeout);
  }
}

function buildBuiltInChecks() {
  return [
    {
      header: 'strict-transport-security',
      message: 'Strict-Transport-Security header is missing',
      validate: (value) => /max-age=\d+/i.test(value),
      invalidMessage: 'Strict-Transport-Security must include max-age',
    },
    {
      header: 'content-security-policy',
      message: 'Content-Security-Policy header is missing',
      validate: (value) => value.trim().length > 0,
      invalidMessage: 'Content-Security-Policy must not be empty',
    },
    {
      header: 'x-content-type-options',
      message: 'X-Content-Type-Options header is missing',
      validate: (value) => value.trim().toLowerCase() === 'nosniff',
      invalidMessage: 'X-Content-Type-Options must be "nosniff"',
    },
    {
      header: 'x-frame-options',
      message: 'X-Frame-Options header is missing',
      validate: (value) => {
        const v = value.trim().toLowerCase();
        return v === 'deny' || v === 'sameorigin' || v.startsWith('allow-from ');
      },
      invalidMessage: 'X-Frame-Options must be DENY, SAMEORIGIN, or ALLOW-FROM <uri>',
    },
    {
      header: 'referrer-policy',
      message: 'Referrer-Policy header is missing',
      validate: (value) => value.trim().length > 0,
      invalidMessage: 'Referrer-Policy must not be empty',
    },
    {
      header: 'permissions-policy',
      message: 'Permissions-Policy header is missing',
      validate: (value) => value.trim().length > 0,
      invalidMessage: 'Permissions-Policy must not be empty',
    },
  ];
}

function buildJobAidChecks() {
  const checks = buildBuiltInChecks();

  checks.push(
    {
      header: 'cross-origin-opener-policy',
      message: 'Cross-Origin-Opener-Policy header is missing',
      validate: (value) => value.trim().toLowerCase() === 'same-origin',
      invalidMessage: 'Cross-Origin-Opener-Policy must be "same-origin"',
    },
    {
      header: 'cross-origin-resource-policy',
      message: 'Cross-Origin-Resource-Policy header is missing',
      validate: (value) => {
        const v = value.trim().toLowerCase();
        return v === 'same-origin' || v === 'same-site';
      },
      invalidMessage: 'Cross-Origin-Resource-Policy must be "same-origin" or "same-site"',
    },
    {
      header: 'cross-origin-embedder-policy',
      message: 'Cross-Origin-Embedder-Policy header is missing',
      validate: (value) => value.trim().toLowerCase() === 'require-corp',
      invalidMessage: 'Cross-Origin-Embedder-Policy must be "require-corp"',
    },
  );

  return checks;
}

function buildChecksForProfile(profileInput) {
  const profile = String(profileInput || DEFAULT_COMPLIANCE_PROFILE).trim().toLowerCase();

  switch (profile) {
    case 'default':
      return buildBuiltInChecks();
    case 'jobaid':
    case 'accenture-jobaid':
      return buildJobAidChecks();
    default:
      throw new Error(
        `Unknown compliance-profile "${profileInput}". Allowed values: default, jobaid, accenture-jobaid.`
      );
  }
}

function parseCustomChecks(raw) {
  if (!raw || !String(raw).trim()) return [];

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`custom-required-headers is not valid JSON: ${error.message}`);
  }

  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('custom-required-headers must be a JSON object');
  }

  return Object.entries(parsed).map(([header, expected]) => {
    const headerName = String(header || '').trim().toLowerCase();
    if (!headerName) {
      throw new Error('custom-required-headers contains an empty header name');
    }

    if (expected === null || expected === undefined || expected === '') {
      return {
        header: headerName,
        message: `${headerName} header is missing`,
        validate: (value) => value.trim().length > 0,
        invalidMessage: `${headerName} must not be empty`,
      };
    }

    return {
      header: headerName,
      message: `${headerName} header is missing`,
      validate: (value) => value.toLowerCase().includes(String(expected).toLowerCase()),
      invalidMessage: `${headerName} must include "${expected}"`,
    };
  });
}

async function getResponse(url, timeoutSeconds) {
  try {
    const head = await fetchWithTimeout(url, 'HEAD', timeoutSeconds);
    if (head.status !== 405 && head.status !== 501) {
      return { method: 'HEAD', response: head };
    }
  } catch {
    // Fall back to GET for endpoints that reject HEAD or gateways that block it.
  }

  const get = await fetchWithTimeout(url, 'GET', timeoutSeconds);
  return { method: 'GET', response: get };
}

async function validateUrl(url, checks, timeoutSeconds) {
  const violations = [];

  if (!isValidUrl(url)) {
    violations.push({
      url,
      header: '(url)',
      message: 'Invalid URL format',
      severity: 'error',
    });
    return { url, statusCode: null, method: 'n/a', violations };
  }

  let fetched;
  try {
    fetched = await getResponse(url, timeoutSeconds);
  } catch (error) {
    violations.push({
      url,
      header: '(request)',
      message: `Request failed: ${error.message}`,
      severity: 'error',
    });
    return { url, statusCode: null, method: 'n/a', violations };
  }

  const { method, response } = fetched;
  const statusCode = response.status;
  const headerMap = normaliseHeaderMap(response.headers);

  for (const check of checks) {
    const value = headerMap[check.header];

    if (value === undefined) {
      violations.push({
        url,
        header: check.header,
        message: check.message,
        severity: 'error',
      });
      continue;
    }

    if (!check.validate(value)) {
      violations.push({
        url,
        header: check.header,
        message: check.invalidMessage,
        actual: value,
        severity: 'error',
      });
    }
  }

  return { url, statusCode, method, violations };
}

async function main() {
  const urls = splitUrls(process.env.INPUT_URLS);
  const timeoutSeconds = parseInteger(process.env.INPUT_TIMEOUT_SECONDS, DEFAULT_TIMEOUT_SECONDS);
  const sarifPath = resolveSarifPath(process.env.INPUT_SARIF_PATH);
  const builtInChecks = buildChecksForProfile(process.env.INPUT_COMPLIANCE_PROFILE);
  const checks = [...builtInChecks, ...parseCustomChecks(process.env.INPUT_CUSTOM_REQUIRED_HEADERS)];

  if (urls.length === 0) {
    throw new Error('No URLs provided. Set input "urls" with one or more HTTP/HTTPS endpoints.');
  }

  const results = [];
  for (const url of urls) {
    const result = await validateUrl(url, checks, timeoutSeconds);
    results.push(result);
  }

  const violations = results.flatMap((r) => r.violations);
  const passed = violations.length === 0;

  writeSarifFile(sarifPath, violations);

  for (const violation of violations) {
    emitErrorAnnotation(violation);
  }

  appendOutput('passed', String(passed));
  appendOutput('violations', JSON.stringify(violations));
  appendOutput('sarif-file', sarifPath);

  const summary = [];
  summary.push('## Secure HTTP Header Check');
  summary.push('');
  summary.push(
    `Compliance profile: ${String(process.env.INPUT_COMPLIANCE_PROFILE || DEFAULT_COMPLIANCE_PROFILE)}`
  );
  summary.push('');
  summary.push(`Checked URLs: ${results.length}`);
  summary.push(`Violations: ${violations.length}`);
  summary.push(`Result: ${passed ? 'PASS' : 'FAIL'}`);
  summary.push('');

  summary.push('| URL | Method | Status | Violations |');
  summary.push('|---|---:|---:|---:|');
  for (const r of results) {
    summary.push(`| ${r.url} | ${r.method} | ${r.statusCode === null ? 'n/a' : r.statusCode} | ${r.violations.length} |`);
  }

  if (violations.length > 0) {
    summary.push('');
    summary.push('### Violations');
    for (const v of violations) {
      summary.push(`- ${v.url} :: ${v.header} -> ${v.message}${v.actual ? ` (actual: ${v.actual})` : ''}`);
    }
  }

  appendSummary(summary);

  if (!passed) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  const sarifPath = resolveSarifPath(process.env.INPUT_SARIF_PATH);
  const runtimeViolation = {
    url: '(action)',
    header: '(runtime)',
    message: error.message,
    severity: 'error',
  };

  writeSarifFile(sarifPath, [runtimeViolation]);
  emitErrorAnnotation(runtimeViolation);

  appendOutput('passed', 'false');
  appendOutput('violations', JSON.stringify([runtimeViolation]));
  appendOutput('sarif-file', sarifPath);

  appendSummary([
    '## Secure HTTP Header Check',
    '',
    'Result: FAIL',
    '',
    `- Runtime error: ${error.message}`,
  ]);

  console.error(error);
  process.exit(1);
});
