#!/usr/bin/env node
'use strict';

/**
 * PM2 MCP server
 * Exposes the core PM2 controls and state as Model Context Protocol tools/resources.
 */
const fs = require('fs');
const z = require('zod');
const { McpServer, ResourceTemplate } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const pkg = require('../../package.json');
const pm2 = require('../..');

const server = new McpServer({
  name: 'pm2-mcp',
  version: pkg.version
});

let isConnected = false;

function renderJson(value) {
  return JSON.stringify(value, null, 2);
}

function textContent(value) {
  return [{ type: 'text', text: typeof value === 'string' ? value : renderJson(value) }];
}

function errorResult(err) {
  return {
    isError: true,
    content: textContent(`Error: ${err.message}`),
    structuredContent: { error: err.message }
  };
}

async function ensureConnected() {
  if (isConnected) return;
  await new Promise((resolve, reject) => {
    const noDaemon = process.env.PM2_MCP_NO_DAEMON === 'true';
    if (process.env.PM2_MCP_DEBUG === 'true') {
      console.error('[pm2-mcp][debug] connecting to PM2 (noDaemon:', noDaemon, ')');
    }
    pm2.connect(noDaemon, err => {
      if (err) return reject(err);
      isConnected = true;
      if (process.env.PM2_MCP_DEBUG === 'true') {
        console.error('[pm2-mcp][debug] connected to PM2');
      }
      return resolve();
    });
  });
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

  server.registerTool(
    'pm2_list_processes',
    {
      title: 'List PM2 processes',
      description: 'Returns the current PM2 process list with basic metrics'
    },
    async () => {
      try {
        await ensureConnected();
        const processes = (await pm2List()).map(formatProcess);
        return {
          content: textContent(processes),
          structuredContent: { processes }
        };
      } catch (err) {
        return errorResult(err);
      }
    }
  );

  server.registerTool(
    'pm2_describe_process',
    {
      title: 'Describe a PM2 process',
      description: 'Returns the full PM2 description for a process id, name, or "all".',
      inputSchema: describeSchema
    },
    async ({ process }) => {
      try {
        await ensureConnected();
        const description = await pm2Describe(process);
        if (!description || description.length === 0) {
          throw new Error(`No process found for "${process}"`);
        }
        return {
          content: textContent(description),
          structuredContent: { description }
        };
      } catch (err) {
        return errorResult(err);
      }
    }
  );

  server.registerTool(
    'pm2_start_process',
    {
      title: 'Start a process with PM2',
      description: 'Start a script or JSON ecosystem file.',
      inputSchema: startSchema
    },
    async args => {
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
    }
  );

  server.registerTool(
    'pm2_restart_process',
    {
      title: 'Restart a PM2 process',
      description: 'Restart a process by id, name, or "all".',
      inputSchema: restartSchema
    },
    async ({ process, updateEnv }) => {
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
    }
  );

  server.registerTool(
    'pm2_reload_process',
    {
      title: 'Reload a PM2 process',
      description: 'Perform a zero-downtime reload (cluster mode only).',
      inputSchema: reloadSchema
    },
    async ({ process, updateEnv }) => {
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
    }
  );

  server.registerTool(
    'pm2_stop_process',
    {
      title: 'Stop a PM2 process',
      description: 'Stop a process by id, name, or "all".',
      inputSchema: stopSchema
    },
    async ({ process }) => {
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
    }
  );

  server.registerTool(
    'pm2_delete_process',
    {
      title: 'Delete a PM2 process',
      description: 'Delete a process by id, name, or "all".',
      inputSchema: deleteSchema
    },
    async ({ process }) => {
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
    }
  );

  server.registerTool(
    'pm2_flush_logs',
    {
      title: 'Flush PM2 logs',
      description: 'Flush log files for a process id, name, or "all".',
      inputSchema: flushSchema
    },
    async ({ process }) => {
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
    }
  );

  server.registerTool(
    'pm2_reload_logs',
    {
      title: 'Reload PM2 logs',
      description: 'Rotate and reopen log files (pm2 reloadLogs).'
    },
    async () => {
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
    }
  );

  server.registerTool(
    'pm2_dump',
    {
      title: 'Dump PM2 process list',
      description: 'Persist the current PM2 process list to the dump file.'
    },
    async () => {
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
    }
  );

  server.registerTool(
    'pm2_tail_logs',
    {
      title: 'Tail PM2 logs',
      description: 'Read the last N lines from a process log file.',
      inputSchema: logsSchema
    },
    async ({ process, type, lines }) => {
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
    }
  );

  server.registerTool(
    'pm2_kill_daemon',
    {
      title: 'Kill PM2 daemon',
      description: 'Stops the PM2 daemon and all managed processes.'
    },
    async () => {
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
    }
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
      const processes = (await pm2List()).map(formatProcess);
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
            text: renderJson(description[0])
          }
        ]
      };
    }
  );
}

async function startMcpServer(options = {}) {
  const transport = options.transport || new StdioServerTransport();

  if (options.env && typeof options.env === 'object') {
    Object.assign(process.env, options.env);
  }

  await ensureConnected();
  registerTools();
  registerResources();

  transport.onclose = () => {
    disconnectPm2().catch(err => {
      console.error('[pm2-mcp] failed to disconnect PM2', err);
    });
  };
  transport.onerror = err => {
    console.error('[pm2-mcp] transport error', err);
  };

  await server.connect(transport);

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

  return { server, transport };
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
