const { app, BrowserWindow, Tray, Menu, ipcMain, shell, nativeImage, Notification, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const Store = require('electron-store');
const fetch = require('node-fetch');

// Ensure output folder exists
function ensureOutputFolder() {
    const outputFolder = store.get('settings.outputFolder');
    if (outputFolder && !fs.existsSync(outputFolder)) {
        fs.mkdirSync(outputFolder, { recursive: true });
    }
    return outputFolder;
}

// System notification helper
function showNotification(title, body, flowId = null) {
    const settings = store.get('settings');
    if (!settings.notifications) return;
    
    const notification = new Notification({
        title,
        body,
        icon: path.join(__dirname, 'icons', 'icon.png')
    });
    
    notification.on('click', () => {
        mainWindow?.show();
        if (flowId) {
            mainWindow?.webContents.send('flow:focus', { flowId });
        }
    });
    
    notification.show();
}

// Add execution to history
function addExecutionHistory(flowId, flowName, status, details = {}) {
    const history = store.get('executionHistory') || [];
    
    history.unshift({
        id: Date.now().toString(),
        flowId,
        flowName,
        status, // 'success', 'error', 'running'
        timestamp: new Date().toISOString(),
        duration: details.duration || 0,
        error: details.error || null,
        outputFile: details.outputFile || null
    });
    
    // Keep last 100 executions
    if (history.length > 100) history.pop();
    
    store.set('executionHistory', history);
    mainWindow?.webContents.send('history:updated');
}

// Persistent storage
const store = new Store({
    name: 'emergentflow-runner',
    defaults: {
        authToken: null,
        userEmail: null,
        flows: [],
        settings: {
            // Paths
            outputFolder: app.getPath('documents') + '/EmergentFlow',
            
            // Ollama
            ollamaUrl: 'http://localhost:11434',
            
            // Startup
            startMinimized: false,
            runOnStartup: false,
            
            // Notifications
            notifications: true,
            notifyOnComplete: true,
            notifyOnError: true,
            
            // Logging
            logRetentionDays: 7,
            maxLogEntries: 1000,
            
            // Execution
            retryFailedFlows: false,
            maxRetries: 3,
            retryDelaySeconds: 60
        },
        // User's own API keys for BYOK
        apiKeys: {
            openai: '',
            anthropic: '',
            groq: '',
            deepseek: '',
            grok: ''
        },
        // Execution history
        executionHistory: []
    }
});

// Globals
let mainWindow = null;
let tray = null;
let isQuitting = false;
const API_URL = 'https://emergentflow.io';

// Flow execution state
const runningFlows = new Map(); // flowId -> { interval, status }
const flowLogs = [];

// ============================================
// WINDOW MANAGEMENT
// ============================================

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 420,
        height: 650,
        minWidth: 380,
        minHeight: 500,
        show: false,
        frame: true,
        resizable: true,
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true,
            preload: path.join(__dirname, 'preload.js')
        },
        icon: path.join(__dirname, 'icons', 'icon.png')
    });

    mainWindow.loadFile(path.join(__dirname, 'index.html'));

    mainWindow.on('close', (e) => {
        if (!isQuitting) {
            e.preventDefault();
            mainWindow.hide();
        }
    });

    mainWindow.once('ready-to-show', () => {
        if (!store.get('settings.startMinimized')) {
            mainWindow.show();
        }
    });
}

function createTray() {
    const iconPath = path.join(__dirname, 'icons', 'tray.png');
    const icon = nativeImage.createFromPath(iconPath);
    tray = new Tray(icon.resize({ width: 16, height: 16 }));

    const contextMenu = Menu.buildFromTemplate([
        { label: 'Show Window', click: () => mainWindow.show() },
        { label: 'Hide to Tray', click: () => mainWindow.hide() },
        { type: 'separator' },
        { label: 'Open Designer', click: () => shell.openExternal(`${API_URL}/app`) },
        { type: 'separator' },
        { label: 'Quit', click: () => { isQuitting = true; app.quit(); }}
    ]);

    tray.setToolTip('EmergentFlow Runner');
    tray.setContextMenu(contextMenu);
    tray.on('click', () => mainWindow.show());
}

// ============================================
// AUTHENTICATION
// ============================================

ipcMain.handle('auth:login', async () => {
    // Open browser to login page with runner callback
    const authUrl = `${API_URL}/auth/runner-login`;
    shell.openExternal(authUrl);
    return { status: 'opened' };
});

ipcMain.handle('auth:setToken', async (event, { token, email }) => {
    store.set('authToken', token);
    store.set('userEmail', email);
    // Immediately sync flows after login
    await syncFlows();
    return { status: 'ok' };
});

ipcMain.handle('auth:logout', async () => {
    store.set('authToken', null);
    store.set('userEmail', null);
    store.set('flows', []);
    stopAllFlows();
    return { status: 'ok' };
});

ipcMain.handle('auth:getStatus', async () => {
    return {
        loggedIn: !!store.get('authToken'),
        email: store.get('userEmail')
    };
});

// ============================================
// FLOW MANAGEMENT
// ============================================

ipcMain.handle('flows:getAll', async () => {
    return store.get('flows') || [];
});

ipcMain.handle('flows:sync', async () => {
    return await syncFlows();
});

async function syncFlows() {
    const token = store.get('authToken');
    if (!token) return { error: 'Not logged in' };

    try {
        const res = await fetch(`${API_URL}/api/runner/flows`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!res.ok) {
            if (res.status === 401) {
                store.set('authToken', null);
                return { error: 'Session expired' };
            }
            throw new Error(`HTTP ${res.status}`);
        }

        const data = await res.json();
        const flows = data.flows || [];
        
        // Preserve local running state
        const currentFlows = store.get('flows') || [];
        flows.forEach(flow => {
            const existing = currentFlows.find(f => f.id === flow.id);
            if (existing) {
                flow.localEnabled = existing.localEnabled;
                flow.lastRun = existing.lastRun;
                flow.runCount = existing.runCount || 0;
            }
        });

        store.set('flows', flows);
        
        // Restart scheduled flows
        flows.forEach(flow => {
            if (flow.localEnabled && flow.schedule) {
                startScheduledFlow(flow);
            }
        });

        addLog('system', 'System', 'info', `Synced ${flows.length} flows`);
        return { flows };
    } catch (err) {
        addLog('system', 'System', 'error', `Sync failed: ${err.message}`);
        return { error: err.message };
    }
}

ipcMain.handle('flows:toggle', async (event, { flowId, enabled }) => {
    const flows = store.get('flows') || [];
    const flow = flows.find(f => f.id === flowId);
    
    if (!flow) return { error: 'Flow not found' };

    flow.localEnabled = enabled;
    store.set('flows', flows);

    if (enabled) {
        if (flow.schedule) {
            startScheduledFlow(flow);
        }
        addLog(flowId, flow.name, 'info', 'Flow enabled');
    } else {
        stopFlow(flowId);
        addLog(flowId, flow.name, 'info', 'Flow disabled');
    }

    return { ok: true };
});

ipcMain.handle('flows:runNow', async (event, flowId) => {
    const flows = store.get('flows') || [];
    const flow = flows.find(f => f.id === flowId);
    
    if (!flow) return { error: 'Flow not found' };

    addLog(flowId, flow.name, 'info', 'Manual run started');
    await executeFlow(flow);
    return { ok: true };
});

ipcMain.handle('flows:stop', async (event, flowId) => {
    stopFlow(flowId);
    return { ok: true };
});

// ============================================
// FLOW EXECUTION ENGINE
// ============================================

async function executeFlow(flow) {
    const flowId = flow.id;
    const startTime = Date.now();
    
    // Mark as running
    runningFlows.set(flowId, { ...runningFlows.get(flowId), status: 'running' });
    mainWindow?.webContents.send('flow:statusChange', { flowId, status: 'running' });
    addExecutionHistory(flowId, flow.name, 'running');

    try {
        addLog(flowId, flow.name, 'info', 'Executing flow...');

        // Build execution order (topological sort)
        const nodes = flow.nodes || [];
        const connections = flow.connections || [];
        const nodeMap = new Map(nodes.map(n => [n.id, { ...n, inputs: {} }]));
        
        // Find start nodes (no incoming connections)
        const hasIncoming = new Set(connections.map(c => c.to));
        const startNodes = nodes.filter(n => !hasIncoming.has(n.id));

        // Execute nodes in order
        const executed = new Set();
        const nodeOutputs = new Map();
        let lastOutput = null;

        async function executeNode(nodeId) {
            if (executed.has(nodeId)) return nodeOutputs.get(nodeId);
            
            const node = nodeMap.get(nodeId);
            if (!node) return null;

            // Get inputs from connected nodes
            const inputs = {};
            for (const conn of connections.filter(c => c.to === nodeId)) {
                const sourceOutput = await executeNode(conn.from);
                if (sourceOutput !== null) {
                    inputs[conn.toPort || 'input'] = sourceOutput[conn.fromPort || 'output'];
                }
            }

            // Execute this node
            const result = await executeNodeByType(node, inputs, flow);
            executed.add(nodeId);
            nodeOutputs.set(nodeId, result);
            
            if (result?.output) lastOutput = result.output;
            
            return result;
        }

        // Execute all terminal nodes (nodes with no outgoing connections)
        const hasOutgoing = new Set(connections.map(c => c.from));
        const terminalNodes = nodes.filter(n => !hasOutgoing.has(n.id));
        
        for (const node of terminalNodes) {
            await executeNode(node.id);
        }

        const duration = Date.now() - startTime;

        // Update run count
        const flows = store.get('flows') || [];
        const storedFlow = flows.find(f => f.id === flowId);
        if (storedFlow) {
            storedFlow.lastRun = new Date().toISOString();
            storedFlow.runCount = (storedFlow.runCount || 0) + 1;
            storedFlow.lastOutput = typeof lastOutput === 'string' ? lastOutput.slice(0, 500) : JSON.stringify(lastOutput).slice(0, 500);
            store.set('flows', flows);
        }

        addLog(flowId, flow.name, 'info', `Flow completed in ${duration}ms`);
        addExecutionHistory(flowId, flow.name, 'success', { duration });
        
        // Notification
        const settings = store.get('settings');
        if (settings.notifyOnComplete) {
            showNotification('Flow Complete', `${flow.name} finished successfully`, flowId);
        }
        
    } catch (err) {
        const duration = Date.now() - startTime;
        addLog(flowId, flow.name, 'error', `Flow failed: ${err.message}`);
        addExecutionHistory(flowId, flow.name, 'error', { duration, error: err.message });
        
        // Error notification
        const settings = store.get('settings');
        if (settings.notifyOnError) {
            showNotification('Flow Error', `${flow.name}: ${err.message}`, flowId);
        }
        
        // Retry logic
        if (settings.retryFailedFlows) {
            const retryCount = (flow._retryCount || 0) + 1;
            if (retryCount <= settings.maxRetries) {
                flow._retryCount = retryCount;
                addLog(flowId, flow.name, 'info', `Retrying in ${settings.retryDelaySeconds}s (attempt ${retryCount}/${settings.maxRetries})`);
                setTimeout(() => executeFlow(flow), settings.retryDelaySeconds * 1000);
            }
        }
    } finally {
        // Restore scheduled status if it was scheduled
        const running = runningFlows.get(flowId);
        if (running?.interval) {
            running.status = 'scheduled';
            mainWindow?.webContents.send('flow:statusChange', { flowId, status: 'scheduled' });
        } else {
            runningFlows.delete(flowId);
            mainWindow?.webContents.send('flow:statusChange', { flowId, status: 'idle' });
        }
    }
}

async function executeNodeByType(node, inputs, flow) {
    const settings = node.settings || node.data || {};
    const type = node.type;

    addLog(flow.id, flow.name, 'info', `Executing: ${node.name || type}`);

    try {
        switch (type) {
            // === INPUT NODES ===
            case 'text_input':
            case 'input':
            case 'prompt':
            case 'textarea':
                return { output: settings.text || settings.value || settings.content || '' };

            case 'start':
            case 'button':
                return { output: 'triggered' };

            // === LLM NODES ===
            case 'llm':
            case 'openai':
            case 'claude':
            case 'anthropic':
            case 'gemini':
            case 'groq':
            case 'deepseek':
            case 'xai':
            case 'grok':
                return await executeLLMNode(node, inputs, settings);

            case 'ollama':
                return await executeOllamaNode(node, inputs, settings);

            case 'agent':
            case 'report_agent':
                return await executeLLMNode(node, inputs, { ...settings, isAgent: true });

            // === HTTP/WEBHOOK NODES ===
            case 'http':
            case 'http_request':
            case 'webhook':
            case 'webhook_out':
            case 'api':
                return await executeHttpNode(node, inputs, settings);

            case 'n8n_trigger':
            case 'zapier_trigger':
            case 'make_trigger':
                return await executeHttpNode(node, inputs, { ...settings, method: 'POST' });

            // === MESSAGING NODES ===
            case 'discord':
                return await executeWebhookNotification(settings.webhookUrl, {
                    content: inputs.input || inputs.message || settings.message || ''
                });

            case 'slack':
                return await executeWebhookNotification(settings.webhookUrl, {
                    text: inputs.input || inputs.message || settings.message || ''
                });

            case 'ntfy':
                return await executeNtfyNode(node, inputs, settings);

            case 'telegram':
                return await executeTelegramNode(node, inputs, settings);

            case 'email':
                return await executeEmailNode(node, inputs, settings);

            // === DATA NODES ===
            case 'json':
            case 'json_parse':
                return executeJsonNode(node, inputs, settings);

            case 'template':
                return executeTemplateNode(node, inputs, settings);

            case 'string':
                return executeStringNode(node, inputs, settings);

            case 'list':
                return executeListNode(node, inputs, settings);

            case 'date':
                return executeDateNode(node, inputs, settings);

            case 'counter':
                return executeCounterNode(node, inputs, settings);

            case 'memory':
            case 'variable':
                return executeMemoryNode(node, inputs, settings);

            // === LOGIC NODES ===
            case 'conditional':
            case 'if':
                return executeConditionalNode(node, inputs, settings);

            case 'router':
            case 'switch':
                return executeRouterNode(node, inputs, settings);

            case 'merge':
            case 'combine':
                return { output: Object.values(inputs).filter(v => v).join('\n') };

            case 'loop':
                return executeLoopNode(node, inputs, settings);

            // === TIMING NODES ===
            case 'delay':
            case 'wait':
                const ms = (settings.seconds || settings.delay || 1) * 1000;
                await new Promise(r => setTimeout(r, ms));
                return inputs;

            case 'timer':
            case 'scheduler':
                // These trigger flows, not produce output
                return { output: 'scheduled', triggered_at: new Date().toISOString() };

            // === CODE NODES ===
            case 'code':
            case 'javascript':
                return await executeCodeNode(node, inputs, settings);

            // === SEARCH NODES ===
            case 'search':
            case 'web':
                return await executeSearchNode(node, inputs, settings);

            // === OUTPUT NODES ===
            case 'viewer':
            case 'output':
            case 'logger':
                const outputVal = inputs.input || inputs.content || Object.values(inputs)[0] || '';
                addLog(flow.id, flow.name, 'info', `Output: ${String(outputVal).slice(0, 500)}`);
                return { output: outputVal };

            case 'save':
            case 'file_output':
            case 'write_file':
                return await executeSaveNode(node, inputs, settings, flow);

            // === UNSUPPORTED (need browser) ===
            case 'html_viewer':
            case 'pdf_viewer':
            case 'image':
            case 'video':
            case 'file':
            case 'audio_player':
            case 'tts':
            case 'serial':
            case 'hid':
            case 'browser_agent':
            case 'screenshot_viewer':
            case 'image_gallery':
            case 'chat':
            case 'python':
                addLog(flow.id, flow.name, 'warn', `Node type '${type}' requires browser - skipped`);
                return inputs;

            default:
                addLog(flow.id, flow.name, 'warn', `Unknown node type: ${type} - passing through`);
                return inputs;
        }
    } catch (err) {
        addLog(flow.id, flow.name, 'error', `Node ${type} failed: ${err.message}`);
        return { error: err.message };
    }
}

async function executeLLMNode(node, inputs, settings) {
    const provider = settings.provider || node.type || 'default';
    
    // Get API key - first check node settings, then runner's stored keys
    const storedKeys = store.get('apiKeys') || {};
    let apiKey = settings.apiKey;
    
    if (!apiKey) {
        // Map provider names to key storage
        const keyMap = {
            'openai': 'openai',
            'anthropic': 'anthropic',
            'claude': 'anthropic',
            'groq': 'groq',
            'deepseek': 'deepseek',
            'xai': 'grok',
            'grok': 'grok'
        };
        apiKey = storedKeys[keyMap[provider] || provider];
    }
    
    const model = settings.model || 'gpt-4';
    const systemPrompt = settings.systemPrompt || settings.system || '';
    
    // Build prompt from inputs
    let prompt = settings.prompt || '';
    for (const [key, value] of Object.entries(inputs)) {
        prompt = prompt.replace(new RegExp(`{{\\s*${key}\\s*}}`, 'g'), value);
        if (!prompt && value) prompt = String(value);
    }

    const token = store.get('authToken');
    
    try {
        const res = await fetch(`${API_URL}/api/generate`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                provider,
                apiKey,
                model,
                prompt,
                system: systemPrompt
            })
        });

        const data = await res.json();
        return { output: data.response || data.error || '' };
    } catch (err) {
        return { output: `LLM Error: ${err.message}` };
    }
}

async function executeOllamaNode(node, inputs, settings) {
    const ollamaUrl = store.get('settings.ollamaUrl') || 'http://localhost:11434';
    const model = settings.model || 'llama2';
    const systemPrompt = settings.systemPrompt || '';
    
    let prompt = settings.prompt || '';
    for (const [key, value] of Object.entries(inputs)) {
        prompt = prompt.replace(`{{${key}}}`, value);
        if (!prompt && value) prompt = value;
    }

    try {
        const messages = [];
        if (systemPrompt) messages.push({ role: 'system', content: systemPrompt });
        messages.push({ role: 'user', content: prompt });

        const res = await fetch(`${ollamaUrl}/api/chat`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                model,
                messages,
                stream: false
            })
        });

        const data = await res.json();
        return { output: data.message?.content || '' };
    } catch (err) {
        return { output: `Ollama Error: ${err.message}` };
    }
}

async function executeHttpNode(node, inputs, settings) {
    const method = settings.method || 'GET';
    let url = settings.url || '';
    
    // Replace placeholders
    for (const [key, value] of Object.entries(inputs)) {
        url = url.replace(`{{${key}}}`, encodeURIComponent(value));
    }

    try {
        const options = {
            method,
            headers: settings.headers || {}
        };

        if (['POST', 'PUT', 'PATCH'].includes(method)) {
            options.body = settings.body || JSON.stringify(inputs);
            options.headers['Content-Type'] = options.headers['Content-Type'] || 'application/json';
        }

        const res = await fetch(url, options);
        const text = await res.text();
        
        try {
            return { output: JSON.parse(text) };
        } catch {
            return { output: text };
        }
    } catch (err) {
        return { output: `HTTP Error: ${err.message}` };
    }
}

async function executeCodeNode(node, inputs, settings) {
    const code = settings.code || '';
    
    try {
        // Create a safe-ish execution context
        const fn = new Function('inputs', `
            ${code}
            return typeof output !== 'undefined' ? output : inputs;
        `);
        const result = fn(inputs);
        return { output: result };
    } catch (err) {
        return { output: `Code Error: ${err.message}` };
    }
}

function executeConditionalNode(node, inputs, settings) {
    const condition = settings.condition || '';
    const inputValue = inputs.input || inputs.value || Object.values(inputs)[0] || '';
    
    let result = false;
    try {
        const fn = new Function('value', 'input', `return ${condition}`);
        result = fn(inputValue, inputValue);
    } catch {
        result = !!inputValue;
    }

    return result ? { true: inputValue } : { false: inputValue };
}

// Additional node execution functions

function executeJsonNode(node, inputs, settings) {
    const input = inputs.input || inputs.data || Object.values(inputs)[0] || '';
    const operation = settings.operation || 'parse';
    
    try {
        if (operation === 'parse' || operation === 'decode') {
            return { output: JSON.parse(input) };
        } else if (operation === 'stringify' || operation === 'encode') {
            return { output: JSON.stringify(input, null, 2) };
        } else if (operation === 'get' && settings.path) {
            const obj = typeof input === 'string' ? JSON.parse(input) : input;
            const value = settings.path.split('.').reduce((o, k) => o?.[k], obj);
            return { output: value };
        }
        return { output: input };
    } catch (e) {
        return { output: input, error: e.message };
    }
}

function executeTemplateNode(node, inputs, settings) {
    let template = settings.template || settings.text || '';
    
    // Replace {{key}} placeholders with input values
    for (const [key, value] of Object.entries(inputs)) {
        template = template.replace(new RegExp(`{{\\s*${key}\\s*}}`, 'g'), value);
    }
    
    // Also replace {{input}} with first input value
    const firstValue = Object.values(inputs)[0] || '';
    template = template.replace(/\{\{\s*input\s*\}\}/g, firstValue);
    
    return { output: template };
}

function executeStringNode(node, inputs, settings) {
    const input = String(inputs.input || Object.values(inputs)[0] || '');
    const operation = settings.operation || 'trim';
    
    switch (operation) {
        case 'trim': return { output: input.trim() };
        case 'uppercase': return { output: input.toUpperCase() };
        case 'lowercase': return { output: input.toLowerCase() };
        case 'split': return { output: input.split(settings.delimiter || ',') };
        case 'join': return { output: Array.isArray(input) ? input.join(settings.delimiter || ',') : input };
        case 'replace': return { output: input.replace(new RegExp(settings.find || '', 'g'), settings.replace || '') };
        case 'slice': return { output: input.slice(settings.start || 0, settings.end) };
        case 'length': return { output: input.length };
        default: return { output: input };
    }
}

function executeListNode(node, inputs, settings) {
    let list = inputs.input || inputs.items || Object.values(inputs)[0] || [];
    if (typeof list === 'string') {
        try { list = JSON.parse(list); } catch { list = list.split('\n'); }
    }
    
    const operation = settings.operation || 'get';
    
    switch (operation) {
        case 'get': return { output: list[settings.index || 0] };
        case 'first': return { output: list[0] };
        case 'last': return { output: list[list.length - 1] };
        case 'length': return { output: list.length };
        case 'join': return { output: list.join(settings.delimiter || ', ') };
        case 'reverse': return { output: [...list].reverse() };
        case 'sort': return { output: [...list].sort() };
        case 'unique': return { output: [...new Set(list)] };
        case 'filter': return { output: list.filter(Boolean) };
        default: return { output: list };
    }
}

function executeDateNode(node, inputs, settings) {
    const now = new Date();
    const format = settings.format || 'iso';
    
    switch (format) {
        case 'iso': return { output: now.toISOString() };
        case 'date': return { output: now.toDateString() };
        case 'time': return { output: now.toTimeString() };
        case 'timestamp': return { output: now.getTime() };
        case 'locale': return { output: now.toLocaleString() };
        default: return { output: now.toISOString() };
    }
}

function executeCounterNode(node, inputs, settings) {
    // Simple counter - in real implementation would persist
    const start = settings.start || 0;
    const step = settings.step || 1;
    node._counter = (node._counter || start) + step;
    return { output: node._counter };
}

function executeMemoryNode(node, inputs, settings) {
    const key = settings.key || 'default';
    const operation = settings.operation || 'get';
    
    // Use a simple in-memory store (persists during runner session)
    if (!global.memoryStore) global.memoryStore = {};
    
    if (operation === 'set') {
        global.memoryStore[key] = inputs.input || inputs.value || Object.values(inputs)[0];
        return { output: global.memoryStore[key] };
    } else {
        return { output: global.memoryStore[key] || settings.default || '' };
    }
}

function executeRouterNode(node, inputs, settings) {
    const input = inputs.input || Object.values(inputs)[0] || '';
    const routes = settings.routes || [];
    
    for (const route of routes) {
        if (route.condition) {
            try {
                const fn = new Function('value', `return ${route.condition}`);
                if (fn(input)) {
                    return { [route.output || 'match']: input };
                }
            } catch {}
        }
    }
    
    return { default: input };
}

function executeLoopNode(node, inputs, settings) {
    let items = inputs.items || inputs.input || [];
    if (typeof items === 'string') {
        try { items = JSON.parse(items); } catch { items = items.split('\n'); }
    }
    
    // For runner, we just pass items through - actual iteration happens in flow execution
    return { 
        items: items,
        count: Array.isArray(items) ? items.length : 0,
        output: items
    };
}

async function executeWebhookNotification(url, body) {
    if (!url) return { error: 'No webhook URL configured' };
    
    try {
        const res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        return { output: res.ok ? 'sent' : 'failed', status: res.status };
    } catch (e) {
        return { error: e.message };
    }
}

async function executeNtfyNode(node, inputs, settings) {
    const topic = settings.topic || 'emergentflow';
    const message = inputs.input || inputs.message || settings.message || '';
    const server = settings.server || 'https://ntfy.sh';
    
    try {
        const res = await fetch(`${server}/${topic}`, {
            method: 'POST',
            body: message,
            headers: settings.title ? { 'Title': settings.title } : {}
        });
        return { output: res.ok ? 'sent' : 'failed' };
    } catch (e) {
        return { error: e.message };
    }
}

async function executeTelegramNode(node, inputs, settings) {
    const token = settings.botToken;
    const chatId = settings.chatId;
    const message = inputs.input || inputs.message || settings.message || '';
    
    if (!token || !chatId) return { error: 'Missing bot token or chat ID' };
    
    try {
        const res = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chat_id: chatId, text: message })
        });
        return { output: res.ok ? 'sent' : 'failed' };
    } catch (e) {
        return { error: e.message };
    }
}

async function executeEmailNode(node, inputs, settings) {
    // Email requires server-side SMTP - route through API
    const token = store.get('authToken');
    if (!token) return { error: 'Not authenticated' };
    
    try {
        const res = await fetch(`${API_URL}/api/send-email`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                to: settings.to || inputs.to,
                subject: settings.subject || inputs.subject || 'EmergentFlow Notification',
                body: inputs.input || inputs.body || settings.body || ''
            })
        });
        const data = await res.json();
        return { output: data.success ? 'sent' : 'failed', ...data };
    } catch (e) {
        return { error: e.message };
    }
}

async function executeSearchNode(node, inputs, settings) {
    const query = inputs.input || inputs.query || settings.query || '';
    const token = store.get('authToken');
    
    if (!token) return { error: 'Not authenticated' };
    
    try {
        const res = await fetch(`${API_URL}/api/search`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ query })
        });
        const data = await res.json();
        return { output: data.results || data };
    } catch (e) {
        return { error: e.message };
    }
}

// Save file to local filesystem
async function executeSaveNode(node, inputs, settings, flow) {
    const content = inputs.input || inputs.content || Object.values(inputs)[0] || '';
    const filename = settings.filename || `output_${Date.now()}`;
    const format = settings.format || 'txt';
    const outputFolder = ensureOutputFolder();
    
    // Build full path
    let fullFilename = filename;
    if (!filename.includes('.')) {
        fullFilename = `${filename}.${format}`;
    }
    
    // Add flow subfolder
    const flowFolder = path.join(outputFolder, flow.name.replace(/[^a-z0-9]/gi, '_'));
    if (!fs.existsSync(flowFolder)) {
        fs.mkdirSync(flowFolder, { recursive: true });
    }
    
    const filePath = path.join(flowFolder, fullFilename);
    
    try {
        let dataToWrite = content;
        
        // Format content based on type
        if (format === 'json') {
            dataToWrite = typeof content === 'string' ? content : JSON.stringify(content, null, 2);
        } else if (format === 'csv') {
            if (Array.isArray(content)) {
                // Convert array to CSV
                if (content.length > 0 && typeof content[0] === 'object') {
                    const headers = Object.keys(content[0]);
                    const rows = content.map(row => headers.map(h => JSON.stringify(row[h] ?? '')).join(','));
                    dataToWrite = [headers.join(','), ...rows].join('\n');
                } else {
                    dataToWrite = content.join('\n');
                }
            }
        }
        
        fs.writeFileSync(filePath, dataToWrite, 'utf-8');
        addLog(flow.id, flow.name, 'info', `Saved: ${filePath}`);
        
        return { output: content, filePath, success: true };
    } catch (e) {
        addLog(flow.id, flow.name, 'error', `Save failed: ${e.message}`);
        return { error: e.message, success: false };
    }
}

// ============================================
// ENHANCED SETTINGS
// ============================================

ipcMain.handle('settings:get', async () => {
    return store.get('settings');
});

ipcMain.handle('settings:save', async (event, settings) => {
    // Ensure output folder exists when changed
    if (settings.outputFolder) {
        if (!fs.existsSync(settings.outputFolder)) {
            fs.mkdirSync(settings.outputFolder, { recursive: true });
        }
    }
    
    store.set('settings', settings);
    
    // Handle auto-start
    if (settings.runOnStartup !== undefined) {
        app.setLoginItemSettings({
            openAtLogin: settings.runOnStartup,
            openAsHidden: settings.startMinimized
        });
    }
    
    return { ok: true };
});

// Shell
ipcMain.handle('shell:openExternal', async (event, url) => {
    shell.openExternal(url);
    return { ok: true };
});

// Folder picker
ipcMain.handle('dialog:selectFolder', async () => {
    const result = await dialog.showOpenDialog(mainWindow, {
        properties: ['openDirectory', 'createDirectory'],
        title: 'Select Output Folder'
    });
    
    if (!result.canceled && result.filePaths.length > 0) {
        return { path: result.filePaths[0] };
    }
    return { path: null };
});

// Open folder in file explorer
ipcMain.handle('shell:openFolder', async (event, folderPath) => {
    const folder = folderPath || store.get('settings.outputFolder');
    if (folder && fs.existsSync(folder)) {
        shell.openPath(folder);
        return { ok: true };
    }
    return { error: 'Folder not found' };
});

// ============================================
// API KEYS (BYOK)
// ============================================

ipcMain.handle('apiKeys:get', async () => {
    return store.get('apiKeys') || {};
});

ipcMain.handle('apiKeys:save', async (event, keys) => {
    store.set('apiKeys', keys);
    return { ok: true };
});

ipcMain.handle('apiKeys:getKey', async (event, provider) => {
    return store.get(`apiKeys.${provider}`) || '';
});

// ============================================
// EXECUTION HISTORY
// ============================================

ipcMain.handle('history:getAll', async () => {
    return store.get('executionHistory') || [];
});

ipcMain.handle('history:clear', async () => {
    store.set('executionHistory', []);
    return { ok: true };
});

ipcMain.handle('history:getForFlow', async (event, flowId) => {
    const history = store.get('executionHistory') || [];
    return history.filter(h => h.flowId === flowId);
});

// ============================================
// SCHEDULING
// ============================================

function parseSchedule(schedule) {
    if (!schedule) return null;
    
    const s = schedule.toLowerCase();
    let intervalMs = null;
    let description = schedule;
    
    // Parse "every X minutes/hours/days"
    if (s.includes('minute')) {
        const match = s.match(/(\d+)\s*minute/);
        intervalMs = (match ? parseInt(match[1]) : 1) * 60000;
        description = `Every ${match ? match[1] : 1} minute${match && match[1] !== '1' ? 's' : ''}`;
    } else if (s.includes('hour')) {
        const match = s.match(/(\d+)\s*hour/);
        intervalMs = (match ? parseInt(match[1]) : 1) * 3600000;
        description = `Every ${match ? match[1] : 1} hour${match && match[1] !== '1' ? 's' : ''}`;
    } else if (s.includes('day')) {
        const match = s.match(/(\d+)\s*day/);
        intervalMs = (match ? parseInt(match[1]) : 1) * 86400000;
        description = `Every ${match ? match[1] : 1} day${match && match[1] !== '1' ? 's' : ''}`;
    } else if (s.includes('second')) {
        const match = s.match(/(\d+)\s*second/);
        intervalMs = (match ? parseInt(match[1]) : 30) * 1000;
        description = `Every ${match ? match[1] : 30} second${match && match[1] !== '1' ? 's' : ''}`;
    } else if (s.includes('week')) {
        const match = s.match(/(\d+)\s*week/);
        intervalMs = (match ? parseInt(match[1]) : 1) * 604800000;
        description = `Every ${match ? match[1] : 1} week${match && match[1] !== '1' ? 's' : ''}`;
    }
    
    return intervalMs ? { intervalMs, description } : null;
}

function getNextRunTime(lastRun, intervalMs) {
    if (!lastRun || !intervalMs) return null;
    const last = new Date(lastRun).getTime();
    const next = last + intervalMs;
    return new Date(next);
}

function startScheduledFlow(flow) {
    stopFlow(flow.id); // Clear any existing schedule

    const schedule = flow.schedule || flow.data?.schedule;
    if (!schedule) return;

    const parsed = parseSchedule(schedule);
    if (!parsed) {
        addLog(flow.id, flow.name, 'warn', `Could not parse schedule: ${schedule}`);
        return;
    }

    const { intervalMs, description } = parsed;
    
    // Store schedule info
    const scheduleInfo = {
        intervalMs,
        description,
        startedAt: new Date().toISOString(),
        nextRun: new Date(Date.now() + intervalMs).toISOString()
    };

    const interval = setInterval(async () => {
        addLog(flow.id, flow.name, 'info', `Scheduled run triggered`);
        await executeFlow(flow);
        
        // Update next run time
        const running = runningFlows.get(flow.id);
        if (running) {
            running.nextRun = new Date(Date.now() + intervalMs).toISOString();
            mainWindow?.webContents.send('flow:scheduleUpdate', { 
                flowId: flow.id, 
                nextRun: running.nextRun 
            });
        }
    }, intervalMs);
    
    runningFlows.set(flow.id, { 
        interval, 
        status: 'scheduled',
        ...scheduleInfo
    });
    
    addLog(flow.id, flow.name, 'info', `Scheduled: ${description} (next: ${scheduleInfo.nextRun})`);
    
    // Notify UI
    mainWindow?.webContents.send('flow:statusChange', { 
        flowId: flow.id, 
        status: 'scheduled',
        schedule: scheduleInfo
    });
}

function stopFlow(flowId) {
    const running = runningFlows.get(flowId);
    if (running?.interval) {
        clearInterval(running.interval);
    }
    runningFlows.delete(flowId);
    mainWindow?.webContents.send('flow:statusChange', { flowId, status: 'idle' });
}

function stopAllFlows() {
    for (const [flowId] of runningFlows) {
        stopFlow(flowId);
    }
}

// Get schedule info for a flow
ipcMain.handle('flows:getScheduleInfo', async (event, flowId) => {
    const running = runningFlows.get(flowId);
    if (!running) return null;
    
    return {
        status: running.status,
        description: running.description,
        intervalMs: running.intervalMs,
        startedAt: running.startedAt,
        nextRun: running.nextRun
    };
});

// Get all running/scheduled flows info
ipcMain.handle('flows:getAllScheduleInfo', async () => {
    const info = {};
    for (const [flowId, running] of runningFlows) {
        info[flowId] = {
            status: running.status,
            description: running.description,
            nextRun: running.nextRun
        };
    }
    return info;
});

// ============================================
// LOGS
// ============================================

function addLog(flowId, flowName, level, message) {
    const entry = {
        timestamp: new Date().toISOString(),
        flowId,
        flowName,
        level,
        message
    };
    
    flowLogs.push(entry);
    if (flowLogs.length > 500) flowLogs.shift();
    
    mainWindow?.webContents.send('log:new', entry);
    console.log(`[${level}] ${flowName}: ${message}`);
}

ipcMain.handle('logs:getAll', async () => {
    return flowLogs;
});

ipcMain.handle('logs:clear', async () => {
    flowLogs.length = 0;
    return { ok: true };
});

// ============================================
// LOCAL HTTP SERVER (for browser integration)
// ============================================

const http = require('http');

function startLocalServer() {
    const server = http.createServer(async (req, res) => {
        // CORS
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

        if (req.method === 'OPTIONS') {
            res.writeHead(200);
            res.end();
            return;
        }

        const url = new URL(req.url, 'http://localhost');

        // GET /status
        if (url.pathname === '/status' && req.method === 'GET') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                ok: true,
                version: '1.0.0',
                active_flows: runningFlows.size,
                total_flows: (store.get('flows') || []).length
            }));
            return;
        }

        // POST /deploy
        if (url.pathname === '/deploy' && req.method === 'POST') {
            let body = '';
            req.on('data', chunk => body += chunk);
            req.on('end', () => {
                try {
                    const flow = JSON.parse(body);
                    const flows = store.get('flows') || [];
                    const idx = flows.findIndex(f => f.id === flow.id);
                    if (idx >= 0) {
                        flows[idx] = { ...flows[idx], ...flow };
                    } else {
                        flows.push(flow);
                    }
                    store.set('flows', flows);
                    mainWindow?.webContents.send('flows:updated');
                    addLog(flow.id, flow.name, 'info', 'Flow deployed from browser');
                    
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ ok: true, flow_id: flow.id }));
                } catch (e) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: e.message }));
                }
            });
            return;
        }

        // POST /auth-callback (receives token from browser OAuth)
        if (url.pathname === '/auth-callback' && req.method === 'POST') {
            let body = '';
            req.on('data', chunk => body += chunk);
            req.on('end', async () => {
                try {
                    const { token, email } = JSON.parse(body);
                    store.set('authToken', token);
                    store.set('userEmail', email);
                    await syncFlows();
                    mainWindow?.webContents.send('auth:updated');
                    mainWindow?.show();
                    
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ ok: true }));
                } catch (e) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: e.message }));
                }
            });
            return;
        }

        res.writeHead(404);
        res.end('Not found');
    });

    server.listen(3742, '127.0.0.1', () => {
        console.log('Local server running on http://127.0.0.1:3742');
    });
}

// ============================================
// APP LIFECYCLE
// ============================================

app.whenReady().then(() => {
    createWindow();
    createTray();
    startLocalServer();

    // Auto-sync on startup if logged in
    if (store.get('authToken')) {
        syncFlows();
    }
});

app.on('window-all-closed', () => {
    // Don't quit on window close - keep running in tray
});

app.on('before-quit', () => {
    isQuitting = true;
    stopAllFlows();
});

app.on('activate', () => {
    if (mainWindow) {
        mainWindow.show();
    }
});
