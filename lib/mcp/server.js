#!/usr/bin/env node
'use strict';

/**
 * PM2 MCP server
 * Exposes the core PM2 controls and state as Model Context Protocol tools/resources.
 */
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { randomUUID } = require('crypto');
const createDebug = require('debug');
const z = require('zod');
const { McpServer, ResourceTemplate } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StreamableHTTPServerTransport } = require('@modelcontextprotocol/sdk/server/streamableHttp.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const pkg = require('../../package.json');

function detectSandbox() {
  const indicators = {
    isSandboxed: false,
    reasons: []
  };

  // Check for common sandbox indicators
  if (process.env.CLAUDE_CODE_SANDBOX === 'true') {
    indicators.isSandboxed = true;
    indicators.reasons.push('CLAUDE_CODE_SANDBOX=true');
  }

  // Check if home directory is writable
  try {
    const homeTest = path.join(os.homedir(), '.pm2-mcp-sandbox-test');
    fs.writeFileSync(homeTest, 'test');
    fs.rmSync(homeTest, { force: true });
  } catch (err) {
    indicators.isSandboxed = true;
    indicators.reasons.push('home directory not writable');
  }

  // Check if we're running with restricted permissions
  if (process.getuid && process.getuid() !== process.geteuid()) {
    indicators.isSandboxed = true;
    indicators.reasons.push('UID mismatch (setuid)');
  }

  return indicators;
}

function resolvePm2Home() {
  const sandboxInfo = detectSandbox();

  if (process.env.PM2_MCP_DEBUG === 'true' && sandboxInfo.isSandboxed) {
    console.error('[pm2-mcp][debug] sandbox detected:', sandboxInfo.reasons.join(', '));
  }

  const candidates = [
    process.env.PM2_HOME,
    process.env.PM2_MCP_HOME,
    path.join(os.homedir(), '.pm2')
  ].filter(Boolean);

  // Prefer tmp for a portable, socket-friendly location, then fall back to the CWD.
  candidates.push(path.join(os.tmpdir(), 'pm2-mcp'));
  candidates.push(path.join(process.cwd(), '.pm2-mcp'));

  for (const candidate of candidates) {
    try {
      fs.mkdirSync(candidate, { recursive: true });
      fs.accessSync(candidate, fs.constants.W_OK);
      const probeFile = path.join(candidate, '.pm2-mcp-write-check');
      fs.writeFileSync(probeFile, 'ok');
      fs.rmSync(probeFile, { force: true });

      if (process.env.PM2_MCP_DEBUG === 'true') {
        console.error('[pm2-mcp][debug] PM2_HOME resolved to', candidate, sandboxInfo.isSandboxed ? '(sandboxed)' : '(normal)');
      }

      return candidate;
    } catch (err) {
      if (process.env.PM2_MCP_DEBUG === 'true') {
        console.error('[pm2-mcp][debug] PM2_HOME not writable', candidate, err.message);
      }
    }
  }

  // Last resort: return the first candidate so pm2 can handle the error.
  return candidates[0];
}

// Set PM2_HOME before requiring PM2 so it uses a writable location even in sandboxed environments.
const resolvedPm2Home = resolvePm2Home();
process.env.PM2_HOME = resolvedPm2Home;
// Silence PM2 CLI noise so we keep stdio clean for the MCP transport.
if (!process.env.PM2_SILENT) process.env.PM2_SILENT = 'true';
if (!process.env.PM2_PROGRAMMATIC) process.env.PM2_PROGRAMMATIC = 'true';
if (process.env.PM2_MCP_DEBUG === 'true') {
  console.error('[pm2-mcp][debug] using PM2_HOME', resolvedPm2Home);
}
const pm2 = require('../..');

const log = createDebug('pm2-mcp');
const logRequests = createDebug('pm2-mcp:req');

const server = new McpServer({
  name: 'pm2-mcp',
  version: pkg.version
});

let isConnected = false;

function renderJson(value) {
  return JSON.stringify(value, null, 2);
}

function textContent(value) {
  if (logRequests.enabled) {
    logRequests('response', typeof value === 'string' ? value : renderJson(value));
  }
  return [{ type: 'text', text: typeof value === 'string' ? value : renderJson(value) }];
}

function errorResult(err) {
  return {
    isError: true,
    content: textContent(`Error: ${err.message}`),
    structuredContent: { error: err.message }
  };
}

let connectionPromise = null;

async function ensureConnected() {
  if (isConnected) return;
  if (connectionPromise) return connectionPromise;
  connectionPromise = (async () => {
    log('connecting to PM2 (noDaemon default true, override with PM2_MCP_NO_DAEMON)');
    await new Promise((resolve, reject) => {
      // Default to no-daemon mode so the MCP server can start without needing an existing PM2 daemon.
      const noDaemon =
        process.env.PM2_MCP_NO_DAEMON === undefined
          ? true
          : process.env.PM2_MCP_NO_DAEMON === 'true';
      log('pm2.connect noDaemon=%s', noDaemon);
      pm2.connect(noDaemon, err => {
        if (err) return reject(err);
        isConnected = true;
        log('connected to PM2');
        return resolve();
      });
    });
  })();
  try {
    await connectionPromise;
  } finally {
    connectionPromise = null;
  }
}

async function disconnectPm2() {
  if (!isConnected) return;
  pm2.disconnect();
  isConnected = false;
}

function cleanOptions(options) {
  return Object.entries(options).reduce((acc, [key, value]) => {
    if (value !== undefined && value !== null) acc[key] = value;
    return acc;
  }, {});
}

function formatProcess(proc) {
  const env = proc.pm2_env || {};
  return {
    name: proc.name,
    pm_id: proc.pm_id,
    pid: proc.pid,
    status: env.status,
    namespace: env.namespace,
    uptime: env.pm_uptime,
    restart_time: env.restart_time,
    cpu: proc.monit ? proc.monit.cpu : undefined,
    memory: proc.monit ? proc.monit.memory : undefined,
    exec_mode: env.exec_mode,
    instances: env.instances,
    script: env.pm_exec_path,
    pm_out_log_path: env.pm_out_log_path,
    pm_err_log_path: env.pm_err_log_path,
    pm_log_path: env.pm_log_path
  };
}

function pm2List() {
  return new Promise((resolve, reject) => {
    pm2.list((err, list) => {
      if (err) return reject(err);
      return resolve(list || []);
    });
  });
}

function pm2Describe(target) {
  return new Promise((resolve, reject) => {
    pm2.describe(target, (err, description) => {
      if (err) return reject(err);
      return resolve(description || []);
    });
  });
}

function pm2Start(target, options) {
  const cleaned = cleanOptions(options || {});
  return new Promise((resolve, reject) => {
    const cb = (err, procs) => (err ? reject(err) : resolve(procs));
    if (Object.keys(cleaned).length > 0) return pm2.start(target, cleaned, cb);
    return pm2.start(target, cb);
  });
}

function pm2Restart(target, options) {
  const cleaned = cleanOptions(options || {});
  return new Promise((resolve, reject) => {
    const cb = (err, procs) => (err ? reject(err) : resolve(procs));
    if (Object.keys(cleaned).length > 0) return pm2.restart(target, cleaned, cb);
    return pm2.restart(target, cb);
  });
}

function pm2Reload(target, options) {
  const cleaned = cleanOptions(options || {});
  return new Promise((resolve, reject) => {
    const cb = (err, procs) => (err ? reject(err) : resolve(procs));
    if (Object.keys(cleaned).length > 0) return pm2.reload(target, cleaned, cb);
    return pm2.reload(target, cb);
  });
}

function pm2Stop(target) {
  return new Promise((resolve, reject) => {
    pm2.stop(target, (err, res) => (err ? reject(err) : resolve(res)));
  });
}

function pm2Delete(target) {
  return new Promise((resolve, reject) => {
    pm2.delete(target, (err, res) => (err ? reject(err) : resolve(res)));
  });
}

function pm2Flush(target) {
  return new Promise((resolve, reject) => {
    pm2.flush(target, err => (err ? reject(err) : resolve(true)));
  });
}

function pm2ReloadLogs() {
  return new Promise((resolve, reject) => {
    pm2.reloadLogs(err => (err ? reject(err) : resolve(true)));
  });
}

function pm2Dump() {
  return new Promise((resolve, reject) => {
    pm2.dump(err => (err ? reject(err) : resolve(true)));
  });
}

function pm2KillDaemon() {
  return new Promise((resolve, reject) => {
    pm2.killDaemon(err => (err ? reject(err) : resolve(true)));
  });
}

function wrapTool(name, handler) {
  return async (...args) => {
    const start = Date.now();
    logRequests('tool %s called with %o', name, args[0] || {});
    try {
      const result = await handler(...args);
      logRequests('tool %s finished in %dms', name, Date.now() - start);
      return result;
    } catch (err) {
      logRequests('tool %s failed in %dms: %s', name, Date.now() - start, err.message);
      throw err;
    }
  };
}

function normalizePath(maybePath) {
  if (!maybePath) return '/mcp';
  return maybePath.startsWith('/') ? maybePath : `/${maybePath}`;
}

function createTransport(options = {}) {
  if (options.transport) {
    return { transport: options.transport, address: 'custom' };
  }

  const type = String(options.transportType || process.env.PM2_MCP_TRANSPORT || 'stdio').toLowerCase();
  log('transport selection', type);
  if (type === 'http' || type === 'sse' || type === 'streamable') {
    const port = Number(options.port ?? process.env.PM2_MCP_PORT ?? 8849);
    const host = options.host ?? process.env.PM2_MCP_HOST ?? '127.0.0.1';
    const pathPart = normalizePath(options.path || process.env.PM2_MCP_PATH || '/mcp');
    const allowedHosts = (process.env.PM2_MCP_ALLOWED_HOSTS || '')
      .split(',')
      .map(s => s.trim())
      .filter(Boolean);
    const allowedOrigins = (process.env.PM2_MCP_ALLOWED_ORIGINS || '')
      .split(',')
      .map(s => s.trim())
      .filter(Boolean);
    const enableDnsRebindingProtection =
      process.env.PM2_MCP_DNS_PROTECTION === 'false' ? false : true;

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      enableDnsRebindingProtection,
      allowedHosts: allowedHosts.length > 0 ? allowedHosts : undefined,
      allowedOrigins: allowedOrigins.length > 0 ? allowedOrigins : undefined,
      enableJsonResponse: true
    });

    const httpServer = http.createServer((req, res) => {
      logRequests('http %s %s', req.method, req.url);
      try {
        const base = `http://${req.headers.host || `${host}:${port}`}`;
        const url = new URL(req.url || '', base);
        if (url.pathname !== pathPart) {
          res.writeHead(404).end('Not Found');
          return;
        }
        transport.handleRequest(req, res).catch(err => {
          console.error('[pm2-mcp] transport request failed', err);
          if (!res.headersSent) res.writeHead(500);
          res.end('Internal Server Error');
        });
      } catch (err) {
        console.error('[pm2-mcp] transport request failed', err);
        if (!res.headersSent) res.writeHead(500);
        res.end('Internal Server Error');
      }
    });

    // Set timeouts to protect against slow HTTP attacks
    httpServer.timeout = HTTP_SERVER_TIMEOUT_MS;
    httpServer.headersTimeout = HTTP_HEADERS_TIMEOUT_MS;
    httpServer.requestTimeout = HTTP_REQUEST_TIMEOUT_MS;
    httpServer.listen(port, host, () => {
      if (process.env.PM2_MCP_DEBUG === 'true') {
        console.error('[pm2-mcp][debug] HTTP transport listening', `${host}:${port}${pathPart}`);
      }
    });

    return { transport, httpServer, address: `http://${host}:${port}${pathPart}` };
  }

  return { transport: new StdioServerTransport(), address: 'stdio' };
}

async function tailFile(filePath, lineCount) {
  const fh = await fs.promises.open(filePath, 'r');
  try {
    const stats = await fh.stat();
    let position = stats.size;
    const chunkSize = 8192;
    let buffer = '';

    while (position > 0 && buffer.split(/\r?\n/).length <= lineCount + 1) {
      const readSize = Math.min(chunkSize, position);
      position -= readSize;
      const result = await fh.read({ buffer: Buffer.alloc(readSize), position });
      buffer = result.buffer.slice(0, result.bytesRead).toString('utf8') + buffer;
    }

    const lines = buffer.trimEnd().split(/\r?\n/);
    return lines.slice(-lineCount);
  } finally {
    await fh.close();
  }
}

const SECRET_KEYS = ['KEY', 'TOKEN', 'SECRET', 'PASSWORD', 'PASS', 'CREDENTIAL', 'API'];

function redactValue(value) {
  if (typeof value !== 'string') return value;
  if (value.length === 0) return value;

  const upper = value.toUpperCase();
  const looksSecret =
    SECRET_KEYS.some(key => upper.includes(key)) ||
    /(?:sk-[A-Za-z0-9]{32,}|gh[pousr]_[A-Za-z0-9]{36,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,48}|[A-Za-z0-9]{40,})/.test(value);

  if (!looksSecret) return value;
  return '***REDACTED***';
}

function filterEnvironment(env = {}, filterList, redactSecrets = true) {
  const target = {};
  const entries = Object.entries(env);
  const shouldFilter = Array.isArray(filterList) && filterList.length > 0;
  for (const [key, value] of entries) {
    if (shouldFilter && !filterList.includes(key)) continue;
    target[key] = redactSecrets ? redactValue(value) : value;
  }
  return target;
}

function sanitizeDescriptionEntry(entry, options = {}) {
  const cloned = JSON.parse(JSON.stringify(entry || {}));
  const env = cloned.pm2_env || {};

  if (!options.includeEnvironment) {
    delete env.env;
    delete env.env_pm2;
  } else {
    env.env = filterEnvironment(env.env, options.environmentFilter, options.redactSecrets);
    env.env_pm2 = filterEnvironment(env.env_pm2, options.environmentFilter, options.redactSecrets);
  }

  cloned.pm2_env = env;
  return cloned;
}

const LOG_PATTERNS = [
  { id: 'copying_blob', label: 'copying_blob', regex: /copying blob|pulling fs layer|pulling|download/i, semanticStatus: 'downloading' },
  { id: 'building', label: 'building_assets', regex: /building|webpack|bundling|compile|transpil/i, semanticStatus: 'processing' },
  { id: 'installing', label: 'installing_dependencies', regex: /install(ing)? packages|npm install|yarn install|pnpm install/i, semanticStatus: 'processing' },
  { id: 'server_listening', label: 'server_listening', regex: /listening on|listening at|server (started|listening)|ready on|running at/i, semanticStatus: 'online' },
  { id: 'health_checks', label: 'healthcheck', regex: /healthcheck|health check/i, semanticStatus: 'online' },
  { id: 'retrying', label: 'retrying', regex: /retry|reconnect|backoff/i, semanticStatus: 'degraded' },
  { id: 'error', label: 'error', regex: /error|exception|traceback|fatal/i, semanticStatus: 'degraded' },
  { id: 'warning', label: 'warning', regex: /warn(ing)?/i, semanticStatus: 'online' }
];

function extractProgressFromLine(line) {
  const percentMatch = line.match(/(\d{1,3})\s?%/);
  if (percentMatch) {
    const pct = Number(percentMatch[1]);
    if (!Number.isNaN(pct) && pct >= 0 && pct <= 100) {
      return { metric: 'percent', current: pct, estimated_total: 100, trend: 'increasing', percent: pct };
    }
  }

  const fractionMatch = line.match(/(\d+)\s*\/\s*(\d+(?:\.\d+)?)(\b|[^\d]|$)/);
  if (fractionMatch) {
    const current = Number(fractionMatch[1]);
    const total = Number(fractionMatch[2]);
    if (!Number.isNaN(current) && !Number.isNaN(total) && total > 0) {
      return {
        metric: 'count',
        current,
        estimated_total: total,
        trend: current >= total ? 'stable' : 'increasing',
        percent: Math.min(100, Math.round((current / total) * 100))
      };
    }
  }
  return null;
}

function analyzeLogPatterns(logLines = []) {
  const detectedPatterns = [];
  const errorsFound = [];
  const warningsFound = [];
  const progressIndicators = [];

  for (const line of logLines) {
    const lower = line.toLowerCase();

    const progress = extractProgressFromLine(line);
    if (progress) {
      progressIndicators.push({
        metric: progress.metric === 'percent' ? 'percent_complete' : 'items_processed',
        current: progress.current,
        estimated_total: progress.estimated_total,
        trend: progress.trend,
        percent: progress.percent
      });
    }

    for (const pattern of LOG_PATTERNS) {
      if (!pattern.regex.test(lower)) continue;
      const entry = detectedPatterns.find(p => p.pattern === pattern.label);
      if (entry) {
        entry.occurrences += 1;
        entry.last_seen = new Date().toISOString();
      } else {
        detectedPatterns.push({
          pattern: pattern.label,
          occurrences: 1,
          last_seen: new Date().toISOString(),
          sample: line,
          semanticStatus: pattern.semanticStatus
        });
      }
    }

    if (/error|exception|fatal/i.test(line)) {
      errorsFound.push({ line });
    } else if (/warn(ing)?/i.test(line)) {
      warningsFound.push({ line });
    }
  }

  const topPattern = detectedPatterns.length > 0 ? detectedPatterns.reduce((a, b) => (a.occurrences >= b.occurrences ? a : b)) : null;

  return { detectedPatterns, errorsFound, warningsFound, progressIndicators, topPattern };
}

async function readRecentLogLines(env = {}, lineCount = 200) {
  const logPath = env.pm_log_path || env.pm_out_log_path || env.pm_err_log_path;
  if (!logPath) return { lines: [], logPath: null, lastModified: null };
  try {
    const [lines, stats] = await Promise.all([tailFile(logPath, lineCount), fs.promises.stat(logPath)]);
    return { lines, logPath, lastModified: stats.mtimeMs };
  } catch {
    return { lines: [], logPath, lastModified: null };
  }
}

function buildSemanticStateFromHeuristics(opts) {
  const { env = {}, monit = {}, logAnalysis, logInfo } = opts;
  const baseStatus = env.status || 'unknown';

  let status = baseStatus === 'online' ? 'online' : baseStatus;
  let context;
  let inferredFrom = 'status';
  let confidence = 0.4;
  let progress;

  if (logAnalysis?.topPattern) {
    status = logAnalysis.topPattern.semanticStatus || status;
    context = logAnalysis.topPattern.sample;
    inferredFrom = 'log_pattern_match';
    confidence = 0.9;
  }

  if (logAnalysis?.progressIndicators?.length) {
    const latest = logAnalysis.progressIndicators[logAnalysis.progressIndicators.length - 1];
    progress = latest.percent ?? latest.current;
  }

  const restartCount = env.restart_time || 0;
  if (baseStatus === 'online' && restartCount >= 3 && confidence < 0.85) {
    status = 'degraded';
    context = `Restarted ${restartCount} times`;
    inferredFrom = 'restart_count';
    confidence = Math.max(confidence, 0.65);
  }

  const cpu = typeof monit.cpu === 'number' ? monit.cpu : null;
  const now = Date.now();
  const logAgeMs = logInfo?.lastModified ? now - logInfo.lastModified : null;
  const uptimeMs = env.pm_uptime || null;

  if (
    baseStatus === 'online' &&
    logAgeMs !== null &&
    uptimeMs &&
    uptimeMs > 2 * 60 * 1000 &&
    logAgeMs > 5 * 60 * 1000 &&
    cpu !== null &&
    cpu < 1
  ) {
    status = 'stuck';
    context = `No logs for ${Math.round(logAgeMs / 60000)}m, cpu ${cpu}%`;
    inferredFrom = 'log_silence';
    confidence = Math.max(confidence, 0.7);
  }

  if (!context) context = `Status ${status}`;

  return {
    status,
    context,
    progress,
    confidence: Number(confidence.toFixed(2)),
    inferred_from: inferredFrom
  };
}

async function buildSemanticState(procLike) {
  const env = procLike.pm2_env || {};
  const monit = procLike.monit || procLike.pm2_env?.monit || {};
  const logInfo = await readRecentLogLines(env, 200);
  const logAnalysis = analyzeLogPatterns(logInfo.lines);
  return buildSemanticStateFromHeuristics({ env, monit, logAnalysis, logInfo });
}

async function enrichProcess(proc) {
  const base = formatProcess(proc);
  base.semantic_state = await buildSemanticState(proc);
  return base;
}

function registerTools() {
  const startSchema = z
    .object({
      script: z.string().trim().optional(),
      jsonConfigFile: z.string().trim().optional(),
      name: z.string().optional(),
      args: z.string().optional(),
      cwd: z.string().optional(),
      watch: z.union([z.boolean(), z.array(z.string())]).optional(),
      instances: z.union([z.number(), z.string()]).optional(),
      env: z.record(z.string(), z.string()).optional(),
      interpreter: z.string().optional()
    })
    .refine(data => data.script || data.jsonConfigFile, {
      message: 'Provide either script or jsonConfigFile'
    });

  const processTargetSchema = z.union([z.string(), z.number()]);

  const restartSchema = z.object({
    process: processTargetSchema,
    updateEnv: z.boolean().optional()
  });

  const reloadSchema = z.object({
    process: processTargetSchema,
    updateEnv: z.boolean().optional()
  });

  const stopSchema = z.object({
    process: processTargetSchema
  });

  const deleteSchema = z.object({
    process: processTargetSchema
  });

  const describeSchema = z.object({
    process: processTargetSchema
  });

  const flushSchema = z.object({
    process: processTargetSchema
  });

  const logsSchema = z.object({
    process: processTargetSchema,
    type: z.enum(['out', 'err', 'combined']).default('out'),
    lines: z.number().int().positive().max(500).default(60)
  });

  const analyzeLogsSchema = z.object({
    process: processTargetSchema,
    timeframe_minutes: z.number().int().positive().max(1440).default(5),
    lines: z.number().int().positive().max(1000).default(400)
  });

  const describeSafeSchema = z.object({
    process: processTargetSchema,
    include_environment: z.boolean().default(false),
    environment_filter: z.array(z.string()).optional(),
    redact_secrets: z.boolean().default(true)
  });

  server.registerTool(
    'pm2_list_processes',
    {
      title: 'List PM2 processes',
      description: 'Returns the current PM2 process list with basic metrics'
    },
    wrapTool('pm2_list_processes', async () => {
      try {
        await ensureConnected();
        const processes = await Promise.all((await pm2List()).map(proc => enrichProcess(proc)));
        return {
          content: textContent(processes),
          structuredContent: { processes }
        };
      } catch (err) {
        return errorResult(err);
      }
    })
  );

  server.registerTool(
    'pm2_describe_process',
    {
      title: 'Describe a PM2 process',
      description: 'Returns the full PM2 description for a process id, name, or "all".',
      inputSchema: describeSchema
    },
    wrapTool('pm2_describe_process', async ({ process }) => {
      try {
        await ensureConnected();
        const description = await pm2Describe(process);
        if (!description || description.length === 0) {
          throw new Error(`No process found for "${process}"`);
        }
        const withState = await Promise.all(
          description.map(async item => ({ ...item, semantic_state: await buildSemanticState(item) }))
        );
        return {
          content: textContent(withState),
          structuredContent: { description: withState }
        };
      } catch (err) {
        return errorResult(err);
      }
    })
  );

  server.registerTool(
    'pm2_start_process',
    {
      title: 'Start a process with PM2',
      description: 'Start a script or JSON ecosystem file.',
      inputSchema: startSchema
    },
    wrapTool('pm2_start_process', async args => {
      try {
        await ensureConnected();
        const target = args.jsonConfigFile || args.script;
        const options = cleanOptions({
          name: args.name,
          args: args.args,
          cwd: args.cwd,
          watch: args.watch,
          instances: args.instances,
          env: args.env,
          interpreter: args.interpreter
        });

        if (process.env.PM2_MCP_DEBUG === 'true') {
          console.error('[pm2-mcp][debug] starting process', target, options);
        }

        await pm2Start(target, options);
        const processes = (await pm2List()).map(formatProcess);
        const summary = {
          action: 'start',
          target,
          options,
          processes
        };

        if (process.env.PM2_MCP_DEBUG === 'true') {
          console.error('[pm2-mcp][debug] started process', target);
        }

        return {
          content: textContent(summary),
          structuredContent: summary
        };
      } catch (err) {
        if (process.env.PM2_MCP_DEBUG === 'true') {
          console.error('[pm2-mcp][debug] start failed', err);
        }
        return errorResult(err);
      }
    })
  );

  server.registerTool(
    'pm2_restart_process',
    {
      title: 'Restart a PM2 process',
      description: 'Restart a process by id, name, or "all".',
      inputSchema: restartSchema
    },
    wrapTool('pm2_restart_process', async ({ process, updateEnv }) => {
      try {
        await ensureConnected();
        await pm2Restart(process, { updateEnv });
        const processes = (await pm2List()).map(formatProcess);
        const summary = { action: 'restart', process, updateEnv, processes };
        return {
          content: textContent(summary),
          structuredContent: summary
        };
      } catch (err) {
        return errorResult(err);
      }
    })
  );

  server.registerTool(
    'pm2_reload_process',
    {
      title: 'Reload a PM2 process',
      description: 'Perform a zero-downtime reload (cluster mode only).',
      inputSchema: reloadSchema
    },
    wrapTool('pm2_reload_process', async ({ process, updateEnv }) => {
      try {
        await ensureConnected();
        await pm2Reload(process, { updateEnv });
        const processes = (await pm2List()).map(formatProcess);
        const summary = { action: 'reload', process, updateEnv, processes };
        return {
          content: textContent(summary),
          structuredContent: summary
        };
      } catch (err) {
        return errorResult(err);
      }
    })
  );

  server.registerTool(
    'pm2_stop_process',
    {
      title: 'Stop a PM2 process',
      description: 'Stop a process by id, name, or "all".',
      inputSchema: stopSchema
    },
    wrapTool('pm2_stop_process', async ({ process }) => {
      try {
        await ensureConnected();
        await pm2Stop(process);
        const processes = (await pm2List()).map(formatProcess);
        const summary = { action: 'stop', process, processes };
        return {
          content: textContent(summary),
          structuredContent: summary
        };
      } catch (err) {
        return errorResult(err);
      }
    })
  );

  server.registerTool(
    'pm2_delete_process',
    {
      title: 'Delete a PM2 process',
      description: 'Delete a process by id, name, or "all".',
      inputSchema: deleteSchema
    },
    wrapTool('pm2_delete_process', async ({ process }) => {
      try {
        await ensureConnected();
        await pm2Delete(process);
        const processes = (await pm2List()).map(formatProcess);
        const summary = { action: 'delete', process, processes };
        return {
          content: textContent(summary),
          structuredContent: summary
        };
      } catch (err) {
        return errorResult(err);
      }
    })
  );

  server.registerTool(
    'pm2_flush_logs',
    {
      title: 'Flush PM2 logs',
      description: 'Flush log files for a process id, name, or "all".',
      inputSchema: flushSchema
    },
    wrapTool('pm2_flush_logs', async ({ process }) => {
      try {
        await ensureConnected();
        await pm2Flush(process);
        return {
          content: textContent({ action: 'flush', process }),
          structuredContent: { action: 'flush', process }
        };
      } catch (err) {
        return errorResult(err);
      }
    })
  );

  server.registerTool(
    'pm2_reload_logs',
    {
      title: 'Reload PM2 logs',
      description: 'Rotate and reopen log files (pm2 reloadLogs).'
    },
    wrapTool('pm2_reload_logs', async () => {
      try {
        await ensureConnected();
        await pm2ReloadLogs();
        return {
          content: textContent({ action: 'reloadLogs' }),
          structuredContent: { action: 'reloadLogs' }
        };
      } catch (err) {
        return errorResult(err);
      }
    })
  );

  server.registerTool(
    'pm2_dump',
    {
      title: 'Dump PM2 process list',
      description: 'Persist the current PM2 process list to the dump file.'
    },
    wrapTool('pm2_dump', async () => {
      try {
        await ensureConnected();
        await pm2Dump();
        return {
          content: textContent({ action: 'dump' }),
          structuredContent: { action: 'dump' }
        };
      } catch (err) {
        return errorResult(err);
      }
    })
  );

  server.registerTool(
    'pm2_tail_logs',
    {
      title: 'Tail PM2 logs',
      description: 'Read the last N lines from a process log file.',
      inputSchema: logsSchema
    },
    wrapTool('pm2_tail_logs', async ({ process, type, lines }) => {
      try {
        await ensureConnected();
        const description = await pm2Describe(process);
        if (!description || description.length === 0) {
          throw new Error(`No process found for "${process}"`);
        }
        const env = description[0].pm2_env || {};
        const logPath =
          type === 'combined'
            ? env.pm_log_path || env.pm_out_log_path || env.pm_err_log_path
            : type === 'out'
              ? env.pm_out_log_path
              : env.pm_err_log_path;

        if (!logPath) throw new Error('No log path found for this process');
        const data = await tailFile(logPath, lines);
        const payload = { process, type, logPath, lines: data };
        return {
          content: textContent(`Last ${lines} lines from ${logPath}:\n${data.join('\n')}`),
          structuredContent: payload
        };
      } catch (err) {
        return errorResult(err);
      }
    })
  );

  server.registerTool(
    'pm2_analyze_logs',
    {
      title: 'Analyze PM2 logs',
      description: 'Parse recent logs for activity, patterns, and errors.',
      inputSchema: analyzeLogsSchema
    },
    wrapTool('pm2_analyze_logs', async ({ process, timeframe_minutes, lines }) => {
      try {
        await ensureConnected();
        const description = await pm2Describe(process);
        if (!description || description.length === 0) {
          throw new Error(`No process found for "${process}"`);
        }
        const env = description[0].pm2_env || {};
        const { lines: logLines, logPath } = await readRecentLogLines(env, lines);
        const logAnalysis = analyzeLogPatterns(logLines);
        const semantic = buildSemanticStateFromHeuristics({
          env,
          monit: description[0].monit,
          logAnalysis,
          logInfo: { lastModified: null }
        });

        let suggested_action = 'none';
        if (logAnalysis.errorsFound.length > 0) suggested_action = 'investigate';
        else if (logAnalysis.topPattern?.semanticStatus === 'downloading') suggested_action = 'wait_for_completion';
        else if (logAnalysis.topPattern?.semanticStatus === 'degraded') suggested_action = 'investigate';

        const payload = {
          process,
          timeframe_minutes,
          analysis: {
            current_activity: logAnalysis.topPattern?.pattern || semantic.status,
            detected_patterns: logAnalysis.detectedPatterns,
            errors_found: logAnalysis.errorsFound,
            warnings_found: logAnalysis.warningsFound,
            progress_indicators: logAnalysis.progressIndicators,
            anomalies: [],
            suggested_action
          },
          meta: {
            log_path: logPath,
            semantic_state: semantic
          }
        };

        return {
          content: textContent(payload),
          structuredContent: payload
        };
      } catch (err) {
        return errorResult(err);
      }
    })
  );

  server.registerTool(
    'pm2_describe_process_safe',
    {
      title: 'Describe a PM2 process (privacy-safe)',
      description: 'Describe a process with optional environment filtering and secret redaction.',
      inputSchema: describeSafeSchema
    },
    wrapTool('pm2_describe_process_safe', async ({ process, include_environment, environment_filter, redact_secrets }) => {
      try {
        await ensureConnected();
        const description = await pm2Describe(process);
        if (!description || description.length === 0) {
          throw new Error(`No process found for "${process}"`);
        }

        const sanitized = await Promise.all(
          description.map(async item => ({
            ...sanitizeDescriptionEntry(item, {
              includeEnvironment: include_environment,
              environmentFilter: environment_filter,
              redactSecrets: redact_secrets
            }),
            semantic_state: await buildSemanticState(item)
          }))
        );

        return {
          content: textContent(sanitized),
          structuredContent: { description: sanitized }
        };
      } catch (err) {
        return errorResult(err);
      }
    })
  );

  server.registerTool(
    'pm2_kill_daemon',
    {
      title: 'Kill PM2 daemon',
      description: 'Stops the PM2 daemon and all managed processes.'
    },
    wrapTool('pm2_kill_daemon', async () => {
      try {
        await ensureConnected();
        await pm2KillDaemon();
        isConnected = false;
        return {
          content: textContent({ action: 'killDaemon' }),
          structuredContent: { action: 'killDaemon' }
        };
      } catch (err) {
        return errorResult(err);
      }
    })
  );
}

function registerResources() {
  server.registerResource(
    'pm2-process-list',
    'pm2://processes',
    {
      title: 'PM2 process list',
      description: 'Current PM2 processes as JSON.',
      mimeType: 'application/json'
    },
    async () => {
      await ensureConnected();
      const processes = await Promise.all((await pm2List()).map(proc => enrichProcess(proc)));
      return {
        contents: [
          {
            uri: 'pm2://processes',
            mimeType: 'application/json',
            text: renderJson(processes)
          }
        ]
      };
    }
  );

  const processTemplate = new ResourceTemplate('pm2://process/{id}', {
    list: async () => {
      await ensureConnected();
      const processes = await pm2List();
      return {
        resources: processes.map(proc => {
          const name = proc.name || `pm_id_${proc.pm_id}`;
          return {
            uri: `pm2://process/${encodeURIComponent(name)}`,
            name,
            description: `Status ${proc.pm2_env ? proc.pm2_env.status : 'unknown'} (pm_id ${proc.pm_id})`,
            mimeType: 'application/json'
          };
        })
      };
    }
  });

  server.registerResource(
    'pm2-process-detail',
    processTemplate,
    {
      title: 'PM2 process detail',
      description: 'Detailed PM2 description for a single process.',
      mimeType: 'application/json'
    },
    async (uri, variables) => {
      await ensureConnected();
      const target = decodeURIComponent(variables.id);
      const description = await pm2Describe(target);
      if (!description || description.length === 0) {
        return {
          contents: [
            {
              uri: uri.href,
              text: `No process found for "${target}"`
            }
          ]
        };
      }

      return {
        contents: [
          {
            uri: uri.href,
            mimeType: 'application/json',
            text: renderJson({ ...description[0], semantic_state: await buildSemanticState(description[0]) })
          }
        ]
      };
    }
  );
}

async function startMcpServer(options = {}) {
  const { transport, httpServer, address } = createTransport(options);

  if (options.env && typeof options.env === 'object') {
    Object.assign(process.env, options.env);
  }

  await ensureConnected();
  registerTools();
  registerResources();

  // Send sandbox status notification to client after connection
  const sandboxInfo = detectSandbox();
  if (sandboxInfo.isSandboxed) {
    // Use a small delay to ensure the client is fully connected
    setTimeout(() => {
      server.sendLoggingMessage({
        level: 'warning',
        logger: 'pm2-mcp',
        data: {
          message: `PM2 MCP server running in sandboxed environment`,
          reasons: sandboxInfo.reasons,
          pm2_home: process.env.PM2_HOME,
          recommendations: [
            'Process management features are available but may have limited access',
            'PM2 daemon is running in no-daemon mode by default',
            'Set PM2_MCP_NO_DAEMON=false to connect to an existing daemon',
            'Set PM2_HOME or PM2_MCP_HOME to specify a writable location'
          ]
        }
      }).catch(err => {
        if (process.env.PM2_MCP_DEBUG === 'true') {
          console.error('[pm2-mcp][debug] failed to send sandbox notification', err);
        }
      });
    }, 100);
  }

  transport.onclose = () => {
    disconnectPm2().catch(err => {
      console.error('[pm2-mcp] failed to disconnect PM2', err);
    });
    if (httpServer) {
      httpServer.close(err => {
        if (err && process.env.PM2_MCP_DEBUG === 'true') {
          console.error('[pm2-mcp][debug] failed to close HTTP server', err);
        }
      });
    }
  };
  transport.onerror = err => {
    console.error('[pm2-mcp] transport error', err);
  };

  await server.connect(transport);

  if (address && process.env.PM2_MCP_DEBUG === 'true') {
    console.error('[pm2-mcp][debug] listening on', address);
  }
  log('MCP server started on %s', address || 'stdio');

  if (options.attachProcessHandlers !== false) {
    const exitHandler = () => {
      disconnectPm2().finally(() => process.exit(0));
    };

    process.once('SIGINT', exitHandler);
    process.once('SIGTERM', exitHandler);
    process.once('exit', () => {
      disconnectPm2().catch(() => {});
    });
  }

  return { server, transport, httpServer, address };
}

if (require.main === module) {
  startMcpServer().catch(err => {
    console.error('[pm2-mcp] Failed to start MCP server', err);
    process.exit(1);
  });
}

module.exports = {
  server,
  startMcpServer
};
