const { app, BrowserWindow, Tray, Menu, ipcMain, shell, nativeImage, Notification, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const Store = require('electron-store');
const fetch = require('node-fetch');
const database = require('./database');

// Ensure output folder exists
function ensureOutputFolder() {
    const outputFolder = store.get('settings.outputFolder');
    if (outputFolder && !fs.existsSync(outputFolder)) {
        fs.mkdirSync(outputFolder, { recursive: true });
    }
    return outputFolder;
}

// Auto-save flow output to timestamped file with proper extension
function autoSaveFlowOutput(flow, output, triggerTime = null) {
    try {
        const baseOutputFolder = store.get('settings.outputFolder') || (app.getPath('documents') + '/EmergentFlow');
        const safeName = flow.name.replace(/[^a-z0-9]/gi, '_') || 'Untitled';
        const outputFolder = flow.outputFolder || path.join(baseOutputFolder, safeName);
        
        // Ensure folder exists
        if (!fs.existsSync(outputFolder)) {
            fs.mkdirSync(outputFolder, { recursive: true });
        }
        
        // Generate timestamped filename
        const now = new Date();
        const timestamp = now.toISOString().replace(/[:.]/g, '-').slice(0, 19);
        const triggerSuffix = triggerTime ? `_${triggerTime.replace(':', '')}` : '';
        
        // Detect content type and determine extension
        const { content, extension, isBinary } = detectContentType(output);
        const filename = `output_${timestamp}${triggerSuffix}.${extension}`;
        const filePath = path.join(outputFolder, filename);
        
        // Write output
        if (isBinary) {
            fs.writeFileSync(filePath, content);
        } else {
            fs.writeFileSync(filePath, content, 'utf-8');
        }
        
        addLog(flow.id, flow.name, 'info', `Auto-saved: ${filename}`);
        return filePath;
    } catch (e) {
        addLog(flow.id, flow.name, 'error', `Auto-save failed: ${e.message}`);
        return null;
    }
}

// Detect content type and return appropriate format
function detectContentType(output) {
    // Handle Buffer or base64 binary data
    if (Buffer.isBuffer(output)) {
        const ext = detectBinaryType(output);
        return { content: output, extension: ext, isBinary: true };
    }
    
    // Handle base64 encoded data
    if (typeof output === 'string') {
        // Check for data URL format (data:image/png;base64,...)
        const dataUrlMatch = output.match(/^data:([^;]+);base64,(.+)$/);
        if (dataUrlMatch) {
            const mimeType = dataUrlMatch[1];
            const base64Data = dataUrlMatch[2];
            const buffer = Buffer.from(base64Data, 'base64');
            const ext = mimeToExtension(mimeType);
            return { content: buffer, extension: ext, isBinary: true };
        }
        
        // Check if it's raw base64 (for images/PDFs)
        if (isLikelyBase64(output)) {
            const buffer = Buffer.from(output, 'base64');
            const ext = detectBinaryType(buffer);
            if (ext !== 'bin') {
                return { content: buffer, extension: ext, isBinary: true };
            }
        }
        
        // Check for HTML
        if (output.trim().startsWith('<!DOCTYPE') || output.trim().startsWith('<html') || 
            (output.includes('<head') && output.includes('<body'))) {
            return { content: output, extension: 'html', isBinary: false };
        }
        
        // Check for SVG
        if (output.trim().startsWith('<svg') || output.includes('xmlns="http://www.w3.org/2000/svg"')) {
            return { content: output, extension: 'svg', isBinary: false };
        }
        
        // Check for XML
        if (output.trim().startsWith('<?xml')) {
            return { content: output, extension: 'xml', isBinary: false };
        }
        
        // Check for CSV (has commas and newlines, multiple rows)
        const lines = output.trim().split('\n');
        if (lines.length > 1 && lines[0].includes(',') && lines.every(l => l.split(',').length === lines[0].split(',').length)) {
            return { content: output, extension: 'csv', isBinary: false };
        }
        
        // Check for JSON
        const trimmed = output.trim();
        if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || 
            (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
            try {
                JSON.parse(trimmed);
                return { content: trimmed, extension: 'json', isBinary: false };
            } catch (e) {
                // Not valid JSON, fall through
            }
        }
        
        // Check for Markdown indicators
        if (output.includes('# ') || output.includes('## ') || output.includes('```') || 
            output.includes('**') || output.includes('- ')) {
            return { content: output, extension: 'md', isBinary: false };
        }
        
        // Default to txt
        return { content: output, extension: 'txt', isBinary: false };
    }
    
    // Handle objects (save as JSON)
    if (typeof output === 'object') {
        return { content: JSON.stringify(output, null, 2), extension: 'json', isBinary: false };
    }
    
    // Default
    return { content: String(output), extension: 'txt', isBinary: false };
}

// Check if string looks like base64
function isLikelyBase64(str) {
    if (str.length < 100) return false;
    const base64Regex = /^[A-Za-z0-9+/=]+$/;
    // Check first 1000 chars to avoid processing huge strings
    return base64Regex.test(str.slice(0, 1000).replace(/\s/g, ''));
}

// Detect binary file type from magic bytes
function detectBinaryType(buffer) {
    if (buffer.length < 4) return 'bin';
    
    // PNG: 89 50 4E 47
    if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) {
        return 'png';
    }
    // JPEG: FF D8 FF
    if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) {
        return 'jpg';
    }
    // GIF: 47 49 46 38
    if (buffer[0] === 0x47 && buffer[1] === 0x49 && buffer[2] === 0x46 && buffer[3] === 0x38) {
        return 'gif';
    }
    // WebP: 52 49 46 46 ... 57 45 42 50
    if (buffer[0] === 0x52 && buffer[1] === 0x49 && buffer[2] === 0x46 && buffer[3] === 0x46 &&
        buffer.length > 11 && buffer[8] === 0x57 && buffer[9] === 0x45 && buffer[10] === 0x42 && buffer[11] === 0x50) {
        return 'webp';
    }
    // PDF: 25 50 44 46
    if (buffer[0] === 0x25 && buffer[1] === 0x50 && buffer[2] === 0x44 && buffer[3] === 0x46) {
        return 'pdf';
    }
    // ZIP/DOCX/XLSX: 50 4B 03 04
    if (buffer[0] === 0x50 && buffer[1] === 0x4B && buffer[2] === 0x03 && buffer[3] === 0x04) {
        return 'zip';
    }
    // BMP: 42 4D
    if (buffer[0] === 0x42 && buffer[1] === 0x4D) {
        return 'bmp';
    }
    
    return 'bin';
}

// Convert MIME type to file extension
function mimeToExtension(mimeType) {
    const mimeMap = {
        'image/png': 'png',
        'image/jpeg': 'jpg',
        'image/jpg': 'jpg',
        'image/gif': 'gif',
        'image/webp': 'webp',
        'image/svg+xml': 'svg',
        'image/bmp': 'bmp',
        'application/pdf': 'pdf',
        'application/json': 'json',
        'text/html': 'html',
        'text/plain': 'txt',
        'text/csv': 'csv',
        'text/xml': 'xml',
        'application/xml': 'xml',
        'text/markdown': 'md',
        'application/zip': 'zip',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'xlsx',
    };
    return mimeMap[mimeType] || 'bin';
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
        output: details.output || null,
        outputFile: details.outputFile || null,
        triggerTime: details.triggerTime || null // For scheduler nodes
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
            
            // Default LLM provider (when nodes use 'default')
            defaultProvider: 'ollama',
            
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
            google: '',
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
const sseClients = new Set(); // SSE connections from browser

// Broadcast event to all SSE clients
function broadcastSSE(event, data) {
    const message = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const client of sseClients) {
        try {
            client.write(message);
        } catch (e) {
            sseClients.delete(client);
        }
    }
}

// Broadcast updated flow list to all SSE clients
function broadcastFlowList() {
    const flows = store.get('flows') || [];
    const flowList = flows.map(f => {
        const running = runningFlows.get(f.id);
        return {
            id: f.id,
            name: f.name,
            enabled: f.localEnabled,
            schedule: f.schedule,
            status: running?.status || (f.localEnabled ? 'IDLE' : 'DISABLED'),
            lastRun: f.lastRun,
            runCount: f.runCount || 0,
            nextRun: running?.nextRun
        };
    });
    broadcastSSE('flow_list', flowList);
}

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

ipcMain.handle('flows:clearAll', async () => {
    // Stop all running flows first
    stopAllFlows();
    // Clear flows from store
    store.set('flows', []);
    addLog('system', 'System', 'info', 'All flows cleared');
    mainWindow?.webContents.send('flows:updated');
    return { ok: true };
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
        const serverFlows = data.flows || [];
        
        // Get current local flows
        const currentFlows = store.get('flows') || [];
        
        // Merge: update existing, add new from server, keep local-only flows
        const mergedFlows = [...currentFlows];
        
        serverFlows.forEach(serverFlow => {
            const existingIdx = mergedFlows.findIndex(f => f.id === serverFlow.id);
            const hasSchedule = serverFlow.schedule || 
                (serverFlow.nodes || []).some(n => n.type === 'scheduler' && n.data?.times?.length > 0) ||
                (serverFlow.nodes || []).some(n => n.type === 'timer' && n.data?.active);
            
            if (existingIdx >= 0) {
                // Update existing flow but preserve local settings
                const existing = mergedFlows[existingIdx];
                mergedFlows[existingIdx] = {
                    ...serverFlow,
                    localEnabled: existing.localEnabled,
                    lastRun: existing.lastRun,
                    runCount: existing.runCount || 0,
                    outputFolder: existing.outputFolder,
                    autoSaveOutput: existing.autoSaveOutput
                };
            } else {
                // New flow from server - auto-enable if scheduled
                serverFlow.localEnabled = hasSchedule;
                mergedFlows.push(serverFlow);
            }
        });

        store.set('flows', mergedFlows);
        
        // Restart scheduled flows (including those with scheduler nodes)
        mergedFlows.forEach(flow => {
            const hasSchedulerNode = (flow.nodes || []).some(n => n.type === 'scheduler' && n.data?.times?.length > 0);
            if (flow.localEnabled && (flow.schedule || hasSchedulerNode)) {
                startScheduledFlow(flow);
            }
        });

        addLog('system', 'System', 'info', `Synced ${serverFlows.length} flows from server, ${mergedFlows.length} total`);
        return { flows: mergedFlows };
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
        // Check for schedule or scheduler node
        const hasSchedulerNode = (flow.nodes || []).some(n => n.type === 'scheduler' && n.data?.times?.length > 0);
        if (flow.schedule || hasSchedulerNode) {
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

ipcMain.handle('flows:delete', async (event, flowId) => {
    stopFlow(flowId);
    const flows = store.get('flows') || [];
    const newFlows = flows.filter(f => f.id !== flowId);
    store.set('flows', newFlows);
    addLog(flowId, 'Flow', 'info', 'Flow removed from runner');
    return { ok: true };
});

ipcMain.handle('flows:setSchedule', async (event, { flowId, schedule }) => {
    const flows = store.get('flows') || [];
    const flow = flows.find(f => f.id === flowId);
    if (!flow) return { error: 'Flow not found' };
    
    // Stop any existing schedule
    stopFlow(flowId);
    
    if (schedule) {
        flow.schedule = schedule;
        flow.localEnabled = true;
        store.set('flows', flows);
        
        // Start the new schedule
        startScheduledFlow(flow);
        addLog(flowId, flow.name, 'info', `Schedule set: ${schedule}`);
    } else {
        delete flow.schedule;
        store.set('flows', flows);
        addLog(flowId, flow.name, 'info', 'Schedule removed');
    }
    
    return { ok: true, schedule: flow.schedule };
});

ipcMain.handle('flows:setOutputFolder', async (event, { flowId, folder }) => {
    const flows = store.get('flows') || [];
    const flow = flows.find(f => f.id === flowId);
    if (flow) {
        flow.outputFolder = folder || null; // null means use default
        store.set('flows', flows);
        return { ok: true, folder: flow.outputFolder };
    }
    return { error: 'Flow not found' };
});

ipcMain.handle('flows:setAutoSave', async (event, { flowId, enabled }) => {
    const flows = store.get('flows') || [];
    const flow = flows.find(f => f.id === flowId);
    if (flow) {
        flow.autoSaveOutput = enabled;
        store.set('flows', flows);
        return { ok: true, autoSaveOutput: flow.autoSaveOutput };
    }
    return { error: 'Flow not found' };
});

ipcMain.handle('flows:getOutputFolder', async (event, flowId) => {
    const flows = store.get('flows') || [];
    const flow = flows.find(f => f.id === flowId);
    if (flow) {
        if (flow.outputFolder) {
            return { folder: flow.outputFolder, isCustom: true };
        } else {
            // Return default path
            const baseFolder = store.get('settings.outputFolder') || (app.getPath('documents') + '/EmergentFlow');
            const safeName = flow.name.replace(/[^a-z0-9]/gi, '_') || 'Untitled';
            return { folder: path.join(baseFolder, safeName), isCustom: false };
        }
    }
    return { error: 'Flow not found' };
});

ipcMain.handle('flows:openOutputFolder', async (event, flowId) => {
    const flows = store.get('flows') || [];
    const flow = flows.find(f => f.id === flowId);
    if (flow) {
        let folder;
        if (flow.outputFolder) {
            folder = flow.outputFolder;
        } else {
            const baseFolder = store.get('settings.outputFolder') || (app.getPath('documents') + '/EmergentFlow');
            const safeName = flow.name.replace(/[^a-z0-9]/gi, '_') || 'Untitled';
            folder = path.join(baseFolder, safeName);
        }
        
        // Create if doesn't exist
        if (!fs.existsSync(folder)) {
            fs.mkdirSync(folder, { recursive: true });
        }
        shell.openPath(folder);
        return { ok: true };
    }
    return { error: 'Flow not found' };
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
    
    // Broadcast to browser
    broadcastSSE('flow_start', { flow_id: flowId, name: flow.name });

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
                    const fromPort = conn.fromPort || 'output';
                    const toPort = conn.toPort || 'input';
                    const value = sourceOutput[fromPort] || sourceOutput.output || sourceOutput.out;
                    inputs[toPort] = value;
                    console.log(`[Flow] ${conn.from} (${fromPort}) -> ${nodeId} (${toPort}):`, value?.toString().slice(0, 50));
                }
            }

            addLog(flowId, flow.name, 'info', `Executing: ${node.type}`);
            console.log(`[Flow] Executing node ${node.type} with inputs:`, Object.keys(inputs));
            
            // Broadcast node start
            broadcastSSE('node_start', { flow_id: flowId, node_id: nodeId, type: node.type });
            
            // Execute this node
            const result = await executeNodeByType(node, inputs, flow);
            executed.add(nodeId);
            nodeOutputs.set(nodeId, result);
            
            console.log(`[Flow] Node ${node.type} output:`, result?.output?.toString().slice(0, 100) || 'none');
            
            // Broadcast node complete
            if (result?.error) {
                broadcastSSE('node_error', { flow_id: flowId, node_id: nodeId, error: result.error });
            } else {
                broadcastSSE('node_complete', { flow_id: flowId, node_id: nodeId, output: result?.output?.toString().slice(0, 200) });
            }
            
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
            
            // Auto-save output to file if enabled
            if (storedFlow.autoSaveOutput && lastOutput) {
                autoSaveFlowOutput(storedFlow, lastOutput);
            }
        }

        addLog(flowId, flow.name, 'info', `Flow completed in ${duration}ms`);
        addExecutionHistory(flowId, flow.name, 'success', { 
            duration, 
            output: typeof lastOutput === 'string' ? lastOutput.slice(0, 2000) : JSON.stringify(lastOutput).slice(0, 2000)
        });
        
        // Broadcast flow complete
        broadcastSSE('flow_complete', { flow_id: flowId, name: flow.name, duration });
        
        // Notification
        const settings = store.get('settings');
        if (settings.notifyOnComplete) {
            showNotification('Flow Complete', `${flow.name} finished successfully`, flowId);
        }
        
    } catch (err) {
        const duration = Date.now() - startTime;
        addLog(flowId, flow.name, 'error', `Flow failed: ${err.message}`);
        addExecutionHistory(flowId, flow.name, 'error', { duration, error: err.message });
        
        // Broadcast flow error
        broadcastSSE('flow_error', { flow_id: flowId, name: flow.name, error: err.message });
        
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

    try {
        switch (type) {
            // === INPUT NODES ===
            case 'text_input':
            case 'input':
            case 'prompt':
            case 'textarea':
                return { output: settings.text || settings.value || settings.content || inputs.input || '' };

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
                return await executeLLMNode(node, inputs, settings, flow);

            case 'ollama':
                // Pass ollamaUrl from flow config
                const ollamaSettings = { ...settings, ollamaUrl: flow.config?.ollamaUrl };
                return await executeOllamaNode(node, inputs, ollamaSettings);

            case 'agent':
            case 'report_agent':
                return await executeAgentNode(node, inputs, settings, flow);

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
                // Timer just triggers - outputs the trigger signal
                return { output: 'triggered', trigger: 'triggered', triggered_at: new Date().toISOString() };
            
            case 'scheduler':
                // Scheduler outputs to specific port based on which time triggered
                const triggeredIndex = node.data?._triggeredPortIndex;
                if (triggeredIndex !== undefined && triggeredIndex !== null) {
                    const times = node.data.times || [];
                    const rawTime = times[triggeredIndex];
                    let outputTime = rawTime;
                    
                    // Format time if 12h format
                    if (node.data.format !== '24h' && rawTime) {
                        let [h, m] = rawTime.split(':');
                        h = parseInt(h);
                        const suffix = h >= 12 ? ' PM' : ' AM';
                        h = h % 12 || 12;
                        outputTime = `${h}:${m}${suffix}`;
                    }
                    
                    // Output to the specific time port (t0, t1, t2, etc.)
                    const result = { 
                        trigger: outputTime, 
                        output: outputTime, 
                        out: outputTime,
                        time: outputTime,
                        index: triggeredIndex
                    };
                    result['t' + triggeredIndex] = outputTime;
                    
                    addLog(flow.id, flow.name, 'info', `Scheduler fired port t${triggeredIndex} (${outputTime})`);
                    return result;
                }
                return { status: 'waiting' };

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

// ============================================
// DIRECT LLM API CALLS (v1.2.0)
// All calls go DIRECTLY to providers - no server proxy!
// This enables true "data never touches our servers" privacy
// ============================================

async function callOpenAIDirect(apiKey, model, prompt, system = '', images = []) {
    const messages = [];
    if (system) messages.push({ role: 'system', content: system });
    
    // Handle vision models
    if (images.length > 0) {
        const content = [{ type: 'text', text: prompt }];
        for (const img of images) {
            content.push({
                type: 'image_url',
                image_url: { url: img.startsWith('data:') ? img : `data:image/jpeg;base64,${img}` }
            });
        }
        messages.push({ role: 'user', content });
    } else {
        messages.push({ role: 'user', content: prompt });
    }
    
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            model: model || 'gpt-4o-mini',
            messages,
            max_tokens: 4096
        })
    });
    
    const data = await response.json();
    if (data.error) throw new Error(data.error.message);
    return { output: data.choices[0].message.content };
}

async function callAnthropicDirect(apiKey, model, prompt, system = '', images = []) {
    const content = [];
    
    // Add images first if present
    for (const img of images) {
        const base64 = img.startsWith('data:') ? img.split(',')[1] : img;
        content.push({
            type: 'image',
            source: {
                type: 'base64',
                media_type: 'image/jpeg',
                data: base64
            }
        });
    }
    
    content.push({ type: 'text', text: prompt });
    
    const response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
            'x-api-key': apiKey,
            'anthropic-version': '2023-06-01',
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            model: model || 'claude-sonnet-4-20250514',
            max_tokens: 4096,
            system: system || undefined,
            messages: [{ role: 'user', content }]
        })
    });
    
    const data = await response.json();
    if (data.error) throw new Error(data.error.message);
    return { output: data.content[0].text };
}

async function callGoogleDirect(apiKey, model, prompt, system = '', images = []) {
    const modelName = model || 'gemini-2.0-flash';
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${modelName}:generateContent?key=${apiKey}`;
    
    const parts = [];
    
    // Add images if present
    for (const img of images) {
        const base64 = img.startsWith('data:') ? img.split(',')[1] : img;
        parts.push({
            inline_data: {
                mime_type: 'image/jpeg',
                data: base64
            }
        });
    }
    
    parts.push({ text: prompt });
    
    const body = {
        contents: [{ parts }],
        generationConfig: {
            maxOutputTokens: 8192
        }
    };
    
    if (system) {
        body.systemInstruction = { parts: [{ text: system }] };
    }
    
    const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
    
    const data = await response.json();
    if (data.error) throw new Error(data.error.message);
    return { output: data.candidates[0].content.parts[0].text };
}

async function callGroqDirect(apiKey, model, prompt, system = '', images = []) {
    const messages = [];
    if (system) messages.push({ role: 'system', content: system });
    
    // Groq vision support
    if (images.length > 0) {
        const content = [{ type: 'text', text: prompt }];
        for (const img of images) {
            content.push({
                type: 'image_url',
                image_url: { url: img.startsWith('data:') ? img : `data:image/jpeg;base64,${img}` }
            });
        }
        messages.push({ role: 'user', content });
    } else {
        messages.push({ role: 'user', content: prompt });
    }
    
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            model: model || 'llama-3.3-70b-versatile',
            messages,
            max_tokens: 4096
        })
    });
    
    const data = await response.json();
    if (data.error) throw new Error(data.error.message);
    return { output: data.choices[0].message.content };
}

async function callDeepSeekDirect(apiKey, model, prompt, system = '') {
    const messages = [];
    if (system) messages.push({ role: 'system', content: system });
    messages.push({ role: 'user', content: prompt });
    
    const response = await fetch('https://api.deepseek.com/v1/chat/completions', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            model: model || 'deepseek-chat',
            messages,
            max_tokens: 4096
        })
    });
    
    const data = await response.json();
    if (data.error) throw new Error(data.error.message);
    return { output: data.choices[0].message.content };
}

async function callXAIDirect(apiKey, model, prompt, system = '', images = []) {
    const messages = [];
    if (system) messages.push({ role: 'system', content: system });
    
    // xAI/Grok vision support
    if (images.length > 0) {
        const content = [{ type: 'text', text: prompt }];
        for (const img of images) {
            content.push({
                type: 'image_url',
                image_url: { url: img.startsWith('data:') ? img : `data:image/jpeg;base64,${img}` }
            });
        }
        messages.push({ role: 'user', content });
    } else {
        messages.push({ role: 'user', content: prompt });
    }
    
    const response = await fetch('https://api.x.ai/v1/chat/completions', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            model: model || 'grok-2-latest',
            messages,
            max_tokens: 4096
        })
    });
    
    const data = await response.json();
    if (data.error) throw new Error(data.error.message);
    return { output: data.choices[0].message.content };
}

// ============================================
// MAIN LLM NODE EXECUTOR - ALL DIRECT CALLS
// ============================================

async function executeLLMNode(node, inputs, settings, flow = {}) {
    const flowConfig = flow.config || {};
    
    // Get provider - flow config takes precedence
    let provider = flowConfig.provider || settings.provider || node.data?.provider || 'ollama';
    if (provider === 'default') {
        provider = store.get('settings.defaultProvider') || 'ollama';
    }
    
    // Normalize provider names
    if (provider === 'gemini') provider = 'google';
    if (provider === 'grok') provider = 'xai';
    if (provider === 'claude') provider = 'anthropic';
    
    // Get model
    const model = settings.model || node.data?.model || flowConfig.model || '';
    const systemPrompt = settings.systemPrompt || settings.system || node.data?.systemPrompt || '';
    
    // Build prompt from inputs
    let prompt = settings.prompt || node.data?.prompt || '';
    for (const [key, value] of Object.entries(inputs)) {
        if (typeof value === 'string') {
            prompt = prompt.replace(new RegExp(`{{\\s*${key}\\s*}}`, 'g'), value);
        }
        if (!prompt && value) prompt = String(value);
    }
    if (!prompt) {
        prompt = inputs.input || inputs.in || inputs.prompt || '';
    }
    
    if (!prompt) {
        return { output: 'Error: No prompt provided' };
    }
    
    // Get images if any
    const images = [];
    if (inputs.images) {
        images.push(...(Array.isArray(inputs.images) ? inputs.images : [inputs.images]));
    }
    if (inputs.image) {
        images.push(inputs.image);
    }
    
    addLog(flow?.id || 'system', flow?.name || 'LLM', 'info', `[DIRECT] ${provider} / ${model}`);
    
    try {
        // === OLLAMA - Direct to local server ===
        if (provider === 'ollama') {
            const ollamaUrl = flowConfig.ollamaUrl || store.get('settings.ollamaUrl') || 'http://localhost:11434';
            return await executeOllamaNode(node, inputs, { ...settings, model, systemPrompt, ollamaUrl });
        }
        
        // === ALL CLOUD PROVIDERS - DIRECT API CALLS ===
        
        // Get API key from stored keys
        const storedKeys = store.get('apiKeys') || {};
        const keyMap = { 
            'xai': 'grok', 
            'anthropic': 'anthropic', 
            'openai': 'openai', 
            'groq': 'groq', 
            'deepseek': 'deepseek', 
            'google': 'google'
        };
        const apiKey = storedKeys[keyMap[provider]] || storedKeys[provider] || '';
        
        if (!apiKey) {
            return { output: `Error: No API key configured for ${provider}. Add your key in Runner Settings > API Keys.` };
        }
        
        switch (provider) {
            case 'openai':
                return await callOpenAIDirect(apiKey, model, prompt, systemPrompt, images);
                
            case 'anthropic':
                return await callAnthropicDirect(apiKey, model, prompt, systemPrompt, images);
                
            case 'google':
                return await callGoogleDirect(apiKey, model, prompt, systemPrompt, images);
                
            case 'groq':
                return await callGroqDirect(apiKey, model, prompt, systemPrompt, images);
                
            case 'deepseek':
                return await callDeepSeekDirect(apiKey, model, prompt, systemPrompt);
                
            case 'xai':
                return await callXAIDirect(apiKey, model, prompt, systemPrompt, images);
                
            default:
                return { output: `Error: Unknown provider '${provider}'` };
        }
        
    } catch (err) {
        addLog(flow?.id || 'system', flow?.name || 'LLM', 'error', `${provider} error: ${err.message}`);
        return { output: `Error: ${err.message}` };
    }
}

async function executeOllamaNode(node, inputs, settings) {
    // Use URL from settings (passed from flow config) or fall back to stored setting
    let ollamaUrl = settings.ollamaUrl || store.get('settings.ollamaUrl') || 'http://localhost:11434';
    
    // Remove trailing slash to prevent double-slash in URL
    ollamaUrl = ollamaUrl.replace(/\/+$/, '');
    
    const model = settings.model || node.data?.model || 'llama2';
    const systemPrompt = settings.systemPrompt || node.data?.systemPrompt || '';
    
    let prompt = settings.prompt || node.data?.prompt || '';
    for (const [key, value] of Object.entries(inputs)) {
        if (typeof value === 'string') {
            prompt = prompt.replace(`{{${key}}}`, value);
        }
        if (!prompt && value) prompt = String(value);
    }
    if (!prompt) {
        prompt = inputs.input || inputs.in || inputs.prompt || '';
    }

    try {
        const messages = [];
        if (systemPrompt) messages.push({ role: 'system', content: systemPrompt });
        messages.push({ role: 'user', content: prompt });
        
        console.log(`[Ollama] POST ${ollamaUrl}/api/chat model=${model} stream=false`);

        const res = await fetch(`${ollamaUrl}/api/chat`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                model,
                messages,
                stream: false
            })
        });

        if (!res.ok) {
            const text = await res.text();
            return { output: `Ollama Error: HTTP ${res.status} - ${text}` };
        }

        const data = await res.json();
        return { output: data.message?.content || '' };
    } catch (err) {
        console.error('[Ollama] Error:', err);
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

// Agent node with tool support
async function executeAgentNode(node, inputs, settings, flow) {
    const goal = inputs.input || inputs.goal || inputs.prompt || settings.prompt || '';
    if (!goal) return { output: '', status: 'waiting for goal' };
    
    const nodes = flow.nodes || [];
    const connections = flow.connections || [];
    
    // Find tool nodes connected to this agent's 'tools' port
    const toolConnections = connections.filter(c => c.to === node.id && c.toPort === 'tools');
    const toolNodes = toolConnections.map(c => nodes.find(n => n.id === c.from)).filter(Boolean);
    
    // Build tool descriptions
    const toolDescriptions = toolNodes.map(toolNode => {
        const toolName = (toolNode.title || toolNode.name || toolNode.type).replace(/[^a-zA-Z0-9_]/g, '_');
        let description = '';
        
        switch(toolNode.type) {
            case 'search':
                description = 'Search the web for information. Input: search query string.';
                break;
            case 'web':
                description = 'Fetch content from a URL. Input: full URL to fetch.';
                break;
            case 'http_request':
            case 'http':
                description = 'Make an HTTP request. Input: URL or JSON body.';
                break;
            case 'llm':
                description = 'Ask an AI model a question. Input: prompt/question.';
                break;
            case 'json':
                description = 'Parse JSON and extract data. Input: JSON string.';
                break;
            case 'template':
                description = 'Fill a template with values. Input: value for placeholder.';
                break;
            case 'string':
                description = 'String manipulation. Input: text to process.';
                break;
            default:
                description = `Execute ${toolNode.type} node. Input: data to process.`;
        }
        
        if (toolNode.data?.toolDescription) {
            description = toolNode.data.toolDescription;
        }
        
        return { name: toolName, description, nodeId: toolNode.id, nodeType: toolNode.type };
    });
    
    const maxSteps = settings.maxSteps || 8;
    const toolList = toolDescriptions.length > 0 
        ? toolDescriptions.map(t => `- ${t.name}: ${t.description}`).join('\n')
        : '(No tools available - answer based on your knowledge)';
    
    const systemPrompt = `You are an autonomous AI agent that completes tasks step by step.

AVAILABLE TOOLS:
${toolList}

INSTRUCTIONS:
1. Think about what you need to do to accomplish the goal
2. If you need to use a tool, respond with ONLY a JSON object:
   {"action": "tool_name", "action_input": "your input to the tool"}
3. Wait for the tool result, then continue reasoning
4. When you have the final answer, respond with ONLY:
   {"action": "Final Answer", "action_input": "your complete answer"}

RULES:
- Use tools when you need external information or computation
- Always output valid JSON for actions
- Be concise but thorough in your final answer`;

    const history = [{ role: 'user', content: `Goal: ${goal}` }];
    const trace = [];
    
    addLog(flow.id, flow.name, 'info', `Agent starting: ${goal.slice(0, 100)}`);
    
    for (let step = 0; step < maxSteps; step++) {
        try {
            const conversationPrompt = history.map(h => 
                h.role === 'user' ? `User: ${h.content}` : `Assistant: ${h.content}`
            ).join('\n') + '\nAssistant:';
            
            // Call LLM
            const llmResult = await executeLLMNode(node, { input: conversationPrompt }, {
                ...settings,
                systemPrompt: systemPrompt,
                system: systemPrompt
            }, flow);
            
            const response = llmResult.output || '';
            trace.push(`Step ${step + 1}: ${response.substring(0, 200)}`);
            history.push({ role: 'assistant', content: response });
            
            // Parse JSON action
            let actionData;
            try {
                const cleanResponse = response.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
                actionData = JSON.parse(cleanResponse);
            } catch {
                history.push({ role: 'user', content: 'Please respond with a valid JSON action.' });
                continue;
            }
            
            const action = actionData.action;
            const actionInput = actionData.action_input;
            
            // Final answer
            if (action === 'Final Answer') {
                addLog(flow.id, flow.name, 'info', `Agent complete after ${step + 1} steps`);
                return { output: actionInput, result: actionInput, trace: trace.join('\n---\n') };
            }
            
            // Find and execute tool
            const tool = toolDescriptions.find(t => t.name === action);
            if (!tool) {
                history.push({ role: 'user', content: `Tool "${action}" not found. Available: ${toolDescriptions.map(t => t.name).join(', ') || 'none'}` });
                continue;
            }
            
            addLog(flow.id, flow.name, 'info', `Agent using tool: ${tool.name}`);
            
            // Execute the tool node
            const toolNode = nodes.find(n => n.id === tool.nodeId);
            if (!toolNode) {
                history.push({ role: 'user', content: 'Tool node not found.' });
                continue;
            }
            
            // Prepare inputs for tool
            const toolInputs = { input: actionInput, query: actionInput, url: actionInput, trigger: true };
            
            // Execute the tool node
            const toolResult = await executeNodeByType(toolNode, toolInputs, flow);
            const resultStr = typeof toolResult.output === 'string' 
                ? toolResult.output 
                : JSON.stringify(toolResult.output || toolResult);
            
            history.push({ role: 'user', content: `Tool result:\n${resultStr.slice(0, 2000)}` });
            
        } catch (e) {
            addLog(flow.id, flow.name, 'error', `Agent step ${step + 1} error: ${e.message}`);
            history.push({ role: 'user', content: `Error: ${e.message}. Please try a different approach.` });
        }
    }
    
    addLog(flow.id, flow.name, 'warn', 'Agent reached max steps without final answer');
    return { output: history[history.length - 1]?.content || '', trace: trace.join('\n---\n') };
}

// Save file to local filesystem
async function executeSaveNode(node, inputs, settings, flow) {
    const content = inputs.input || inputs.content || Object.values(inputs)[0] || '';
    const filename = settings.filename || `output_${Date.now()}`;
    const format = settings.format || 'txt';
    
    // Get output folder - check flow-specific first, then default
    const flows = store.get('flows') || [];
    const storedFlow = flows.find(f => f.id === flow.id);
    const baseOutputFolder = store.get('settings.outputFolder') || (app.getPath('documents') + '/EmergentFlow');
    
    let outputFolder;
    if (storedFlow?.outputFolder) {
        // Use flow-specific output folder
        outputFolder = storedFlow.outputFolder;
    } else {
        // Default: flowName subfolder inside base output folder
        const safeName = flow.name.replace(/[^a-z0-9]/gi, '_') || 'Untitled';
        outputFolder = path.join(baseOutputFolder, safeName);
    }
    
    // Ensure folder exists
    if (!fs.existsSync(outputFolder)) {
        fs.mkdirSync(outputFolder, { recursive: true });
    }
    
    // Build full path
    let fullFilename = filename;
    if (!filename.includes('.')) {
        fullFilename = `${filename}.${format}`;
    }
    
    const filePath = path.join(outputFolder, fullFilename);
    
    try {
        let dataToWrite = content;
        let isBinary = false;
        
        // Check for binary data (Buffer, base64 images/PDFs)
        if (Buffer.isBuffer(content)) {
            dataToWrite = content;
            isBinary = true;
        } else if (typeof content === 'string') {
            // Check for data URL format (data:image/png;base64,...)
            const dataUrlMatch = content.match(/^data:([^;]+);base64,(.+)$/);
            if (dataUrlMatch) {
                dataToWrite = Buffer.from(dataUrlMatch[2], 'base64');
                isBinary = true;
            } else if (isLikelyBase64(content) && ['png', 'jpg', 'jpeg', 'gif', 'webp', 'pdf', 'bmp'].includes(format)) {
                // Raw base64 with binary format specified
                dataToWrite = Buffer.from(content, 'base64');
                isBinary = true;
            }
        }
        
        // Format text content based on type (only if not binary)
        if (!isBinary) {
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
            } else if (typeof content === 'object') {
                dataToWrite = JSON.stringify(content, null, 2);
            }
        }
        
        // Write file
        if (isBinary) {
            fs.writeFileSync(filePath, dataToWrite);
        } else {
            fs.writeFileSync(filePath, dataToWrite, 'utf-8');
        }
        
        addLog(flow.id, flow.name, 'info', `Saved: ${filePath}`);
        
        return { output: isBinary ? `[Binary file saved: ${fullFilename}]` : content, filePath, success: true };
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

// Open output folder
ipcMain.handle('shell:openOutputFolder', async () => {
    const folder = store.get('settings.outputFolder');
    if (folder) {
        // Create if doesn't exist
        if (!fs.existsSync(folder)) {
            fs.mkdirSync(folder, { recursive: true });
        }
        shell.openPath(folder);
        return { ok: true };
    }
    return { error: 'Output folder not configured' };
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

// Track outputs per time slot for scheduler nodes
const schedulerOutputs = new Map(); // flowId -> { "09:00": { output, timestamp }, "12:00": {...} }

function startScheduledFlow(flow) {
    stopFlow(flow.id); // Clear any existing schedule

    // Check for scheduler node with specific times
    const schedulerNode = (flow.nodes || []).find(n => n.type === 'scheduler');
    if (schedulerNode && schedulerNode.data?.times?.length > 0) {
        startTimeBasedScheduler(flow, schedulerNode);
        return;
    }

    // Otherwise use interval-based schedule
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
        type: 'interval',
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

function startTimeBasedScheduler(flow, schedulerNode) {
    const times = schedulerNode.data.times || [];
    if (times.length === 0) return;
    
    // Calculate next run time
    const now = new Date();
    const todayTimes = times.map(t => {
        const [h, m] = t.split(':');
        const d = new Date();
        d.setHours(parseInt(h), parseInt(m), 0, 0);
        return { time: t, date: d };
    }).sort((a, b) => a.date - b.date);
    
    // Find next upcoming time
    let nextRun = todayTimes.find(t => t.date > now);
    if (!nextRun) {
        // All times passed today, next is first time tomorrow
        nextRun = todayTimes[0];
        nextRun.date.setDate(nextRun.date.getDate() + 1);
    }
    
    const scheduleInfo = {
        type: 'times',
        times: times,
        description: `Daily at ${times.join(', ')}`,
        startedAt: new Date().toISOString(),
        nextRun: nextRun.date.toISOString(),
        nextTime: nextRun.time
    };
    
    // Check every second for time matches
    const interval = setInterval(() => {
        const current = new Date();
        const currentTime = current.toTimeString().slice(0, 5); // "HH:MM"
        
        times.forEach((time, index) => {
            if (time === currentTime) {
                const key = `${flow.id}_${time}_${current.toDateString()}`;
                const running = runningFlows.get(flow.id);
                
                // Prevent firing multiple times in the same minute
                if (running && running._lastFiredKey !== key) {
                    running._lastFiredKey = key;
                    
                    addLog(flow.id, flow.name, 'info', `Time trigger: ${time}`);
                    
                    // Execute with time index info
                    executeFlowWithTimeInfo(flow, index, time);
                    
                    // Update next run
                    updateNextScheduledTime(flow.id, times);
                }
            }
        });
    }, 1000);
    
    runningFlows.set(flow.id, {
        interval,
        status: 'scheduled',
        ...scheduleInfo
    });
    
    addLog(flow.id, flow.name, 'info', `Scheduler active: ${times.length} times (${times.join(', ')})`);
    
    mainWindow?.webContents.send('flow:statusChange', {
        flowId: flow.id,
        status: 'scheduled',
        schedule: scheduleInfo
    });
}

async function executeFlowWithTimeInfo(flow, timeIndex, triggerTime) {
    const startTime = Date.now();
    const flowId = flow.id;
    
    // Set the triggered port index on scheduler node
    const schedulerNode = (flow.nodes || []).find(n => n.type === 'scheduler');
    if (schedulerNode) {
        schedulerNode.data._triggeredPortIndex = timeIndex;
    }
    
    try {
        // Execute flow
        runningFlows.set(flowId, { ...runningFlows.get(flowId), status: 'running' });
        mainWindow?.webContents.send('flow:statusChange', { flowId, status: 'running' });
        
        broadcastSSE('flow_start', { flow_id: flowId, name: flow.name, triggerTime });
        
        const nodes = flow.nodes || [];
        const connections = flow.connections || [];
        const nodeOutputs = new Map();
        const executed = new Set();
        let lastOutput = '';
        
        // Find connections from the triggered scheduler port
        const triggeredPort = 't' + timeIndex;
        const schedulerConnections = connections.filter(c => 
            c.from === schedulerNode?.id && 
            (c.fromPort === triggeredPort || c.fromPort === 'trigger' || c.fromPort === 'output')
        );
        
        async function executeNode(nodeId, fromPort = null) {
            if (executed.has(nodeId)) return nodeOutputs.get(nodeId);
            const node = nodes.find(n => n.id === nodeId);
            if (!node) return null;
            
            // Skip scheduler node's non-triggered ports
            if (node.type === 'scheduler' && fromPort && fromPort !== triggeredPort && fromPort !== 'trigger' && fromPort !== 'output') {
                return null;
            }
            
            const inputs = {};
            for (const conn of connections.filter(c => c.to === nodeId)) {
                // For scheduler connections, only get value if it's from the triggered port
                if (conn.from === schedulerNode?.id) {
                    const connPort = conn.fromPort || 'output';
                    if (connPort !== triggeredPort && connPort !== 'trigger' && connPort !== 'output') {
                        continue; // Skip non-triggered ports
                    }
                }
                
                const sourceOutput = await executeNode(conn.from, conn.fromPort);
                if (sourceOutput !== null) {
                    const fromPortName = conn.fromPort || 'output';
                    const toPort = conn.toPort || 'input';
                    
                    // Get value from specific port, or fallback
                    let value;
                    if (sourceOutput[fromPortName] !== undefined) {
                        value = sourceOutput[fromPortName];
                    } else if (sourceOutput.output !== undefined) {
                        value = sourceOutput.output;
                    } else if (sourceOutput.out !== undefined) {
                        value = sourceOutput.out;
                    }
                    
                    if (value !== undefined) {
                        inputs[toPort] = value;
                    }
                }
            }
            
            const result = await executeNodeByType(node, inputs, flow);
            executed.add(nodeId);
            nodeOutputs.set(nodeId, result);
            
            if (result?.output) lastOutput = result.output;
            return result;
        }
        
        // Start execution from nodes directly connected to triggered scheduler port
        if (schedulerConnections.length > 0) {
            // Execute downstream from scheduler
            for (const conn of schedulerConnections) {
                await executeNode(conn.to);
            }
            
            // Also execute any end nodes that depend on what we just executed
            const endNodeIds = nodes
                .filter(n => !connections.some(c => c.from === n.id))
                .filter(n => !executed.has(n.id))
                .map(n => n.id);
            
            for (const nodeId of endNodeIds) {
                // Check if this end node has a path from executed nodes
                const hasExecutedDependency = connections.some(c => 
                    c.to === nodeId && executed.has(c.from)
                );
                if (hasExecutedDependency || connections.filter(c => c.to === nodeId).length === 0) {
                    await executeNode(nodeId);
                }
            }
        } else {
            // No specific port connections, execute from end nodes
            const endNodeIds = nodes
                .filter(n => !connections.some(c => c.from === n.id))
                .map(n => n.id);
            
            for (const nodeId of endNodeIds) {
                await executeNode(nodeId);
            }
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
            
            // Auto-save output to file if enabled
            if (storedFlow.autoSaveOutput && lastOutput) {
                autoSaveFlowOutput(storedFlow, lastOutput, triggerTime);
            }
        }
        
        // Store output for this time slot
        if (!schedulerOutputs.has(flowId)) {
            schedulerOutputs.set(flowId, {});
        }
        schedulerOutputs.get(flowId)[triggerTime] = {
            output: typeof lastOutput === 'string' ? lastOutput.slice(0, 2000) : JSON.stringify(lastOutput).slice(0, 2000),
            timestamp: new Date().toISOString(),
            duration
        };
        
        addLog(flowId, flow.name, 'info', `Flow completed in ${duration}ms (trigger: ${triggerTime})`);
        addExecutionHistory(flowId, flow.name, 'success', { 
            duration, 
            output: typeof lastOutput === 'string' ? lastOutput.slice(0, 2000) : JSON.stringify(lastOutput).slice(0, 2000),
            triggerTime
        });
        
        broadcastSSE('flow_complete', { flow_id: flowId, name: flow.name, duration, triggerTime });
        
        // Restore scheduled status
        const running = runningFlows.get(flowId);
        if (running) {
            running.status = 'scheduled';
            mainWindow?.webContents.send('flow:statusChange', { flowId, status: 'scheduled' });
        }
        
    } catch (err) {
        const duration = Date.now() - startTime;
        addLog(flowId, flow.name, 'error', `Flow failed: ${err.message}`);
        addExecutionHistory(flowId, flow.name, 'error', { duration, error: err.message, triggerTime });
        
        // Restore scheduled status
        const running = runningFlows.get(flowId);
        if (running) {
            running.status = 'scheduled';
            mainWindow?.webContents.send('flow:statusChange', { flowId, status: 'scheduled' });
        }
    }
}

function updateNextScheduledTime(flowId, times) {
    const now = new Date();
    const todayTimes = times.map(t => {
        const [h, m] = t.split(':');
        const d = new Date();
        d.setHours(parseInt(h), parseInt(m), 0, 0);
        return { time: t, date: d };
    }).sort((a, b) => a.date - b.date);
    
    let nextRun = todayTimes.find(t => t.date > now);
    if (!nextRun) {
        nextRun = { ...todayTimes[0] };
        nextRun.date = new Date(todayTimes[0].date);
        nextRun.date.setDate(nextRun.date.getDate() + 1);
    }
    
    const running = runningFlows.get(flowId);
    if (running) {
        running.nextRun = nextRun.date.toISOString();
        running.nextTime = nextRun.time;
        mainWindow?.webContents.send('flow:scheduleUpdate', {
            flowId,
            nextRun: running.nextRun,
            nextTime: running.nextTime
        });
    }
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
            type: running.type || 'interval',
            times: running.times || null,
            nextRun: running.nextRun,
            nextTime: running.nextTime || null,
            timeOutputs: schedulerOutputs.get(flowId) || {}
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

        // GET /events - Server-Sent Events for live updates
        if (url.pathname === '/events' && req.method === 'GET') {
            res.writeHead(200, {
                'Content-Type': 'text/event-stream',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'Access-Control-Allow-Origin': '*'
            });
            
            // Send initial connected event
            res.write(`event: connected\ndata: ${JSON.stringify({ ok: true, flows: store.get('flows')?.length || 0 })}\n\n`);
            
            // Add to SSE clients
            sseClients.add(res);
            
            // Send flow list with full details
            const flows = store.get('flows') || [];
            const flowList = flows.map(f => {
                const running = runningFlows.get(f.id);
                return {
                    id: f.id,
                    name: f.name,
                    enabled: f.localEnabled,
                    schedule: f.schedule,
                    status: running?.status || (f.localEnabled ? 'IDLE' : 'DISABLED'),
                    lastRun: f.lastRun,
                    runCount: f.runCount || 0,
                    nextRun: running?.nextRun
                };
            });
            res.write(`event: flow_list\ndata: ${JSON.stringify(flowList)}\n\n`);
            
            // Keep connection alive
            const keepAlive = setInterval(() => {
                res.write(': keepalive\n\n');
            }, 30000);
            
            req.on('close', () => {
                clearInterval(keepAlive);
                sseClients.delete(res);
            });
            
            return;
        }

        // GET /status
        if (url.pathname === '/status' && req.method === 'GET') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                ok: true,
                version: '1.2.0',
                active_flows: runningFlows.size,
                total_flows: (store.get('flows') || []).length,
                privacy: 'direct-api-calls'
            }));
            return;
        }
        
        // GET /flows - Get all flows with status
        if (url.pathname === '/flows' && req.method === 'GET') {
            const flows = store.get('flows') || [];
            const flowList = flows.map(f => {
                const running = runningFlows.get(f.id);
                return {
                    id: f.id,
                    name: f.name,
                    enabled: f.localEnabled,
                    schedule: f.schedule,
                    status: running?.status || (f.localEnabled ? 'IDLE' : 'DISABLED'),
                    lastRun: f.lastRun,
                    runCount: f.runCount || 0,
                    nextRun: running?.nextRun
                };
            });
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(flowList));
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
                    
                    // Check if flow has schedule
                    const hasSchedule = flow.schedule || 
                        (flow.nodes || []).some(n => n.type === 'scheduler' && n.data?.times?.length > 0) ||
                        (flow.nodes || []).some(n => n.type === 'timer' && n.data?.active);
                    
                    if (idx >= 0) {
                        // Preserve some local settings when updating
                        const existing = flows[idx];
                        flows[idx] = { 
                            ...flow,
                            localEnabled: existing.localEnabled ?? hasSchedule,
                            runCount: existing.runCount || 0,
                            lastRun: existing.lastRun,
                            outputFolder: existing.outputFolder,
                            autoSaveOutput: existing.autoSaveOutput
                        };
                    } else {
                        // New flow - auto-enable if it has a schedule
                        flow.localEnabled = hasSchedule;
                        flows.push(flow);
                    }
                    store.set('flows', flows);
                    mainWindow?.webContents.send('flows:updated');
                    addLog(flow.id, flow.name, 'info', 'Flow deployed from browser');
                    
                    // Auto-start if it has a schedule
                    const savedFlow = flows.find(f => f.id === flow.id);
                    if (savedFlow && savedFlow.localEnabled && hasSchedule) {
                        startScheduledFlow(savedFlow);
                        addLog(flow.id, flow.name, 'info', 'Schedule started automatically');
                    }
                    
                    // Broadcast updated flow list to browser
                    broadcastFlowList();
                    
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
        
        // POST /flows/:id/run - Run a flow immediately
        const runMatch = url.pathname.match(/^\/flows\/([^/]+)\/run$/);
        if (runMatch && req.method === 'POST') {
            const flowId = runMatch[1];
            const flows = store.get('flows') || [];
            const flow = flows.find(f => f.id === flowId);
            
            if (!flow) {
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Flow not found' }));
                return;
            }
            
            addLog(flowId, flow.name, 'info', 'Manual run triggered from browser');
            executeFlow(flow);
            
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: true }));
            return;
        }
        
        // POST /flows/:id/toggle - Enable/disable a flow
        const toggleMatch = url.pathname.match(/^\/flows\/([^/]+)\/toggle$/);
        if (toggleMatch && req.method === 'POST') {
            const flowId = toggleMatch[1];
            let body = '';
            req.on('data', chunk => body += chunk);
            req.on('end', () => {
                try {
                    const { enabled } = JSON.parse(body);
                    const flows = store.get('flows') || [];
                    const flow = flows.find(f => f.id === flowId);
                    
                    if (!flow) {
                        res.writeHead(404, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ error: 'Flow not found' }));
                        return;
                    }
                    
                    flow.localEnabled = enabled;
                    store.set('flows', flows);
                    
                    if (enabled && flow.schedule) {
                        startScheduledFlow(flow);
                    } else {
                        stopFlow(flowId);
                    }
                    
                    addLog(flowId, flow.name, 'info', enabled ? 'Flow enabled via browser' : 'Flow disabled via browser');
                    mainWindow?.webContents.send('flows:updated');
                    broadcastFlowList();
                    
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ ok: true }));
                } catch (e) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: e.message }));
                }
            });
            return;
        }
        
        // DELETE /flows/:id - Remove a flow
        const deleteMatch = url.pathname.match(/^\/flows\/([^/]+)$/);
        if (deleteMatch && req.method === 'DELETE') {
            const flowId = deleteMatch[1];
            const flows = store.get('flows') || [];
            const flow = flows.find(f => f.id === flowId);
            
            if (flow) {
                stopFlow(flowId);
                const newFlows = flows.filter(f => f.id !== flowId);
                store.set('flows', newFlows);
                addLog(flowId, flow.name, 'info', 'Flow removed via browser');
                mainWindow?.webContents.send('flows:updated');
                broadcastFlowList();
            }
            
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: true }));
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
    database.registerDatabaseIPC();

    // Auto-sync on startup if logged in
    if (store.get('authToken')) {
        syncFlows();
    }
});

app.on('window-all-closed', () => {
    // Don't quit on window close - keep running in tray
});

app.on('before-quit', async () => {
    isQuitting = true;
    stopAllFlows();
    await database.cleanup();
});

app.on('activate', () => {
    if (mainWindow) {
        mainWindow.show();
    }
});
