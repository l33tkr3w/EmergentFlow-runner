const { contextBridge, ipcRenderer, shell } = require('electron');

contextBridge.exposeInMainWorld('runner', {
    // Auth
    login: () => ipcRenderer.invoke('auth:login'),
    setToken: (token, email) => ipcRenderer.invoke('auth:setToken', { token, email }),
    logout: () => ipcRenderer.invoke('auth:logout'),
    getAuthStatus: () => ipcRenderer.invoke('auth:getStatus'),

    // Flows
    getFlows: () => ipcRenderer.invoke('flows:getAll'),
    clearAllFlows: () => ipcRenderer.invoke('flows:clearAll'),
    syncFlows: () => ipcRenderer.invoke('flows:sync'),
    toggleFlow: (flowId, enabled) => ipcRenderer.invoke('flows:toggle', { flowId, enabled }),
    runFlow: (flowId) => ipcRenderer.invoke('flows:runNow', flowId),
    stopFlow: (flowId) => ipcRenderer.invoke('flows:stop', flowId),
    deleteFlow: (flowId) => ipcRenderer.invoke('flows:delete', flowId),
    setFlowOutputFolder: (flowId, folder) => ipcRenderer.invoke('flows:setOutputFolder', { flowId, folder }),
    getFlowOutputFolder: (flowId) => ipcRenderer.invoke('flows:getOutputFolder', flowId),
    openFlowOutputFolder: (flowId) => ipcRenderer.invoke('flows:openOutputFolder', flowId),
    setAutoSave: (flowId, enabled) => ipcRenderer.invoke('flows:setAutoSave', { flowId, enabled }),
    setSchedule: (flowId, schedule) => ipcRenderer.invoke('flows:setSchedule', { flowId, schedule }),
    getScheduleInfo: (flowId) => ipcRenderer.invoke('flows:getScheduleInfo', flowId),
    getAllScheduleInfo: () => ipcRenderer.invoke('flows:getAllScheduleInfo'),

    // Logs
    getLogs: () => ipcRenderer.invoke('logs:getAll'),
    clearLogs: () => ipcRenderer.invoke('logs:clear'),

    // Settings
    getSettings: () => ipcRenderer.invoke('settings:get'),
    saveSettings: (settings) => ipcRenderer.invoke('settings:save', settings),

    // API Keys (BYOK)
    getApiKeys: () => ipcRenderer.invoke('apiKeys:get'),
    saveApiKeys: (keys) => ipcRenderer.invoke('apiKeys:save', keys),
    getApiKey: (provider) => ipcRenderer.invoke('apiKeys:getKey', provider),

    // Execution History
    getHistory: () => ipcRenderer.invoke('history:getAll'),
    clearHistory: () => ipcRenderer.invoke('history:clear'),
    getFlowHistory: (flowId) => ipcRenderer.invoke('history:getForFlow', flowId),

    // Shell/Dialog
    openExternal: (url) => ipcRenderer.invoke('shell:openExternal', url),
    selectFolder: () => ipcRenderer.invoke('dialog:selectFolder'),
    openFolder: (path) => ipcRenderer.invoke('shell:openFolder', path),
    openOutputFolder: () => ipcRenderer.invoke('shell:openOutputFolder'),

    // Events
    onFlowStatus: (callback) => ipcRenderer.on('flow:statusChange', (e, data) => callback(data)),
    onScheduleUpdate: (callback) => ipcRenderer.on('flow:scheduleUpdate', (e, data) => callback(data)),
    onNewLog: (callback) => ipcRenderer.on('log:new', (e, data) => callback(data)),
    onFlowsUpdated: (callback) => ipcRenderer.on('flows:updated', () => callback()),
    onAuthUpdated: (callback) => ipcRenderer.on('auth:updated', () => callback()),
    onHistoryUpdated: (callback) => ipcRenderer.on('history:updated', () => callback()),
    onFlowFocus: (callback) => ipcRenderer.on('flow:focus', (e, data) => callback(data))
});

// Database APIs - exposed as electronAPI for web app compatibility
contextBridge.exposeInMainWorld('electronAPI', {
    // PostgreSQL
    executePostgres: (config) => ipcRenderer.invoke('db:postgres', config),
    
    // MySQL
    executeMysql: (config) => ipcRenderer.invoke('db:mysql', config),
    
    // SQLite
    executeSqlite: (config) => ipcRenderer.invoke('db:sqlite', config),
    
    // MongoDB
    executeMongodb: (config) => ipcRenderer.invoke('db:mongodb', config),
    
    // Redis
    executeRedis: (config) => ipcRenderer.invoke('db:redis', config),
    
    // Test connection
    testDatabaseConnection: (type, config) => ipcRenderer.invoke('db:test', { type, config }),
    
    // Close all database connections
    closeDatabaseConnections: () => ipcRenderer.invoke('db:closeAll')
});
