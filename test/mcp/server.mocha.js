/* eslint-disable no-console */
'use strict';

const path = require('path');
const fs = require('fs');
const os = require('os');
const should = require('should');
const { Client } = require('@modelcontextprotocol/sdk/client');
const { InMemoryTransport } = require('@modelcontextprotocol/sdk/inMemory.js');

const fixturesDir = path.join(__dirname, '..', 'fixtures');

describe('PM2 MCP server', function () {
  this.timeout(30000);

  let client;
  let clientTransport;
  let serverTransport;
  let serverHandle;
  let pm2Home;
  let startMcpServer;
  let shuttingDown = false;

  async function callToolWithTimeout(name, args, timeoutMs = 20000) {
    let timer;
    try {
      const params = { name, arguments: args || {} };
      return await Promise.race([
        client.callTool(params),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error(`callTool ${name} timed out`)), timeoutMs);
        })
      ]);
    } finally {
      clearTimeout(timer);
    }
  }

  async function startClient() {
    pm2Home = fs.mkdtempSync(path.join(os.tmpdir(), 'pm2-mcp-test-'));
    process.env.PM2_HOME = pm2Home;
    process.env.PM2_SILENT = 'true';
    process.env.PM2_PROGRAMMATIC = 'true';

    if (!startMcpServer) {
      // Load lazily so PM2 reads the test-scoped env vars.
      ({ startMcpServer } = require('../../lib/mcp/server'));
    }
    [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    client = new Client({
      name: 'pm2-mcp-test-client',
      version: '1.0.0'
    });
    client.onerror = err => {
      // Helpful when debugging unexpected transport issues.
      console.error('MCP client error', err);
    };
    client.onclose = () => {
      if (!shuttingDown) console.error('MCP client closed unexpectedly');
    };
    const serverPromise = startMcpServer({
      transport: serverTransport,
      attachProcessHandlers: false,
      env: {
        PM2_HOME: pm2Home,
        PM2_SILENT: 'true',
        PM2_PROGRAMMATIC: 'true'
      }
    });
    await client.connect(clientTransport);
    serverHandle = await serverPromise;
  }

  async function stopClient() {
    shuttingDown = true;
    if (client) {
      try {
        await callToolWithTimeout('pm2_kill_daemon');
      } catch (_) {
        /* ignore */
      }
      await client.close().catch(() => {});
    }
    if (serverHandle && serverHandle.transport) {
      await serverHandle.transport.close().catch(() => {});
    }
    if (pm2Home) {
      fs.rmSync(pm2Home, { recursive: true, force: true });
      pm2Home = null;
    }
  }

  async function startEcho(name) {
    const script = path.join(fixturesDir, 'echo.js');
    const res = await callToolWithTimeout('pm2_start_process', {
      script,
      name
    });
    should(res.isError).not.equal(true);
    return res;
  }

  before(async () => {
    await startClient();
  });

  after(async () => {
    await stopClient();
  });

  it('registers expected tools and resources', async () => {
    const tools = await client.listTools();
    const toolNames = tools.tools.map(t => t.name);
    should(toolNames).containEql('pm2_list_processes');
    should(toolNames).containEql('pm2_start_process');
    should(toolNames).containEql('pm2_stop_process');
    should(toolNames).containEql('pm2_tail_logs');
    should(toolNames).containEql('pm2_kill_daemon');

    const resources = await client.listResources();
    const resourceUris = resources.resources.map(r => r.uri);
    should(resourceUris).containEql('pm2://processes');

    const templates = await client.listResourceTemplates();
    const templateUris = templates.resourceTemplates.map(t => t.uriTemplate);
    should(templateUris).containEql('pm2://process/{id}');
  });

  it('runs the happy path: start, list, describe, tail, stop, delete', async () => {
    const name = 'mcp-echo';
    await startEcho(name);

    // Wait a bit so the process has time to emit logs.
    await new Promise(resolve => setTimeout(resolve, 400));

    const listRes = await callToolWithTimeout('pm2_list_processes', {});
    should(listRes.isError).not.equal(true);
    const processNames = (listRes.structuredContent.processes || []).map(p => p.name);
    should(processNames).containEql(name);

    const describeRes = await callToolWithTimeout('pm2_describe_process', { process: name });
    should(describeRes.isError).not.equal(true);
    should(describeRes.structuredContent.description[0].pm2_env.name).eql(name);

    const tailRes = await callToolWithTimeout('pm2_tail_logs', {
      process: name,
      type: 'out',
      lines: 5
    });
    should(tailRes.isError).not.equal(true);
    should(tailRes.structuredContent.lines.join('\n')).match(/echo\.js/);

    await callToolWithTimeout('pm2_stop_process', { process: name });
    await callToolWithTimeout('pm2_delete_process', { process: name });
  });

  it('returns a structured error when targeting an unknown process', async () => {
    const res = await callToolWithTimeout('pm2_describe_process', { process: '__unknown__' });
    should(res.isError).eql(true);
    should(res.structuredContent.error).match(/No process found/);
  });

  it('exposes per-process resource template entries', async () => {
    const name = 'mcp-resource-echo';
    await startEcho(name);
    await new Promise(resolve => setTimeout(resolve, 200));

    const resources = await client.listResources({ cursor: 'pm2://process/{id}' }).catch(() => null);
    // If the client does not support cursor-based listing, fall back to template list+read.
    if (resources && resources.resources && resources.resources.length > 0) {
      const uris = resources.resources.map(r => r.uri);
      const processUri = uris.find(u => decodeURIComponent(u).endsWith(name));
      should(processUri).be.ok();
      const readRes = await client.readResource({ uri: processUri });
      should(readRes.contents[0].text).match(new RegExp(name));
    } else {
      const templates = await client.listResourceTemplates();
      const template = templates.resourceTemplates.find(t => t.uriTemplate === 'pm2://process/{id}');
      should(template).be.ok();
      const readRes = await client.readResource({
        uri: `pm2://process/${encodeURIComponent(name)}`
      });
      should(readRes.contents[0].text).match(new RegExp(name));
    }

    await callToolWithTimeout('pm2_delete_process', { process: name });
  });
});
