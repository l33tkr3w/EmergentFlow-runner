// === EMERGENTFLOW RUNNER - DATABASE MODULE ===
// Provides direct database connectivity for PostgreSQL, MySQL, SQLite, MongoDB, Redis

const { ipcMain } = require('electron');

// Lazy-loaded database clients (only load when needed)
let pgPool = null;
let mysqlPool = null;
let sqliteDb = null;
let mongoClient = null;
let redisClient = null;

// Connection caches to avoid reconnecting on every query
const connectionCache = {
    postgres: new Map(),
    mysql: new Map(),
    sqlite: new Map(),
    mongodb: new Map(),
    redis: new Map()
};

// ============================================================
// POSTGRESQL
// ============================================================

async function getPostgresClient(config) {
    const key = `${config.host}:${config.port}:${config.database}:${config.user}`;
    
    if (connectionCache.postgres.has(key)) {
        return connectionCache.postgres.get(key);
    }
    
    // Lazy load pg
    if (!pgPool) {
        try {
            const { Pool } = require('pg');
            pgPool = Pool;
        } catch (e) {
            throw new Error('PostgreSQL driver not installed. Run: npm install pg');
        }
    }
    
    const pool = new pgPool({
        host: config.host || 'localhost',
        port: config.port || 5432,
        database: config.database,
        user: config.user || 'postgres',
        password: config.password,
        ssl: config.ssl === 'require' ? { rejectUnauthorized: false } : 
             config.ssl === true ? true : false,
        max: 10,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 10000,
    });
    
    // Test connection
    const client = await pool.connect();
    client.release();
    
    connectionCache.postgres.set(key, pool);
    console.log(`[DB] PostgreSQL connected to ${config.host}:${config.port}/${config.database}`);
    
    return pool;
}

async function executePostgres(config) {
    const pool = await getPostgresClient(config);
    const params = config.params || [];
    
    const result = await pool.query(config.query, params);
    
    return {
        rows: result.rows,
        rowCount: result.rowCount,
        fields: result.fields?.map(f => f.name) || []
    };
}

// ============================================================
// MYSQL
// ============================================================

async function getMysqlClient(config) {
    const key = `${config.host}:${config.port}:${config.database}:${config.user}`;
    
    if (connectionCache.mysql.has(key)) {
        return connectionCache.mysql.get(key);
    }
    
    // Lazy load mysql2
    let mysql;
    try {
        mysql = require('mysql2/promise');
    } catch (e) {
        throw new Error('MySQL driver not installed. Run: npm install mysql2');
    }
    
    const pool = mysql.createPool({
        host: config.host || 'localhost',
        port: config.port || 3306,
        database: config.database,
        user: config.user || 'root',
        password: config.password,
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0,
        connectTimeout: 10000
    });
    
    // Test connection
    const conn = await pool.getConnection();
    conn.release();
    
    connectionCache.mysql.set(key, pool);
    console.log(`[DB] MySQL connected to ${config.host}:${config.port}/${config.database}`);
    
    return pool;
}

async function executeMysql(config) {
    const pool = await getMysqlClient(config);
    const params = config.params || [];
    
    const [rows, fields] = await pool.execute(config.query, params);
    
    // Handle different query types
    if (Array.isArray(rows)) {
        return {
            rows: rows,
            rowCount: rows.length,
            fields: fields?.map(f => f.name) || []
        };
    } else {
        // INSERT, UPDATE, DELETE results
        return {
            rows: [],
            rowCount: rows.affectedRows,
            insertId: rows.insertId,
            affectedRows: rows.affectedRows,
            changedRows: rows.changedRows
        };
    }
}

// ============================================================
// SQLITE
// ============================================================

function getSqliteClient(config) {
    const key = config.file;
    
    if (connectionCache.sqlite.has(key)) {
        return connectionCache.sqlite.get(key);
    }
    
    // Lazy load better-sqlite3
    let Database;
    try {
        Database = require('better-sqlite3');
    } catch (e) {
        throw new Error('SQLite driver not installed. Run: npm install better-sqlite3');
    }
    
    const options = {
        readonly: config.mode === 'readonly',
        fileMustExist: config.mode === 'readonly'
    };
    
    const db = new Database(config.file, options);
    
    // Enable WAL mode for better concurrency
    if (config.mode !== 'readonly') {
        db.pragma('journal_mode = WAL');
    }
    
    connectionCache.sqlite.set(key, db);
    console.log(`[DB] SQLite opened: ${config.file}`);
    
    return db;
}

function executeSqlite(config) {
    const db = getSqliteClient(config);
    const params = config.params || [];
    const query = config.query.trim();
    
    // Determine if this is a read or write query
    const isSelect = /^SELECT/i.test(query);
    
    if (isSelect) {
        const stmt = db.prepare(query);
        const rows = stmt.all(...params);
        return {
            rows: rows,
            rowCount: rows.length
        };
    } else {
        const stmt = db.prepare(query);
        const result = stmt.run(...params);
        return {
            rows: [],
            rowCount: result.changes,
            lastInsertRowid: result.lastInsertRowid,
            changes: result.changes
        };
    }
}

// ============================================================
// MONGODB
// ============================================================

async function getMongoClient(config) {
    const key = config.uri;
    
    if (connectionCache.mongodb.has(key)) {
        const cached = connectionCache.mongodb.get(key);
        // Check if still connected
        try {
            await cached.db('admin').command({ ping: 1 });
            return cached;
        } catch (e) {
            connectionCache.mongodb.delete(key);
        }
    }
    
    // Lazy load mongodb
    let MongoClient;
    try {
        const mongodb = require('mongodb');
        MongoClient = mongodb.MongoClient;
    } catch (e) {
        throw new Error('MongoDB driver not installed. Run: npm install mongodb');
    }
    
    const client = new MongoClient(config.uri, {
        maxPoolSize: 10,
        serverSelectionTimeoutMS: 10000,
        connectTimeoutMS: 10000
    });
    
    await client.connect();
    
    connectionCache.mongodb.set(key, client);
    console.log(`[DB] MongoDB connected to ${config.uri.split('@')[1] || config.uri}`);
    
    return client;
}

async function executeMongodb(config) {
    const client = await getMongoClient(config);
    const db = client.db(config.database);
    const collection = db.collection(config.collection);
    
    const action = config.action || 'find';
    const filter = config.filter || {};
    const document = config.document;
    
    let result;
    
    switch (action) {
        case 'find':
            result = await collection.find(filter).limit(config.limit || 100).toArray();
            return { documents: result, matchedCount: result.length };
            
        case 'findOne':
            result = await collection.findOne(filter);
            return { documents: result ? [result] : [], matchedCount: result ? 1 : 0 };
            
        case 'insertOne':
            result = await collection.insertOne(document);
            return { insertedId: result.insertedId, insertedCount: 1 };
            
        case 'insertMany':
            const docs = Array.isArray(document) ? document : [document];
            result = await collection.insertMany(docs);
            return { insertedIds: result.insertedIds, insertedCount: result.insertedCount };
            
        case 'updateOne':
            result = await collection.updateOne(filter, { $set: document });
            return { matchedCount: result.matchedCount, modifiedCount: result.modifiedCount };
            
        case 'updateMany':
            result = await collection.updateMany(filter, { $set: document });
            return { matchedCount: result.matchedCount, modifiedCount: result.modifiedCount };
            
        case 'deleteOne':
            result = await collection.deleteOne(filter);
            return { deletedCount: result.deletedCount };
            
        case 'deleteMany':
            result = await collection.deleteMany(filter);
            return { deletedCount: result.deletedCount };
            
        case 'aggregate':
            const pipeline = Array.isArray(filter) ? filter : [filter];
            result = await collection.aggregate(pipeline).toArray();
            return { documents: result, matchedCount: result.length };
            
        case 'count':
            result = await collection.countDocuments(filter);
            return { count: result };
            
        default:
            throw new Error(`Unknown MongoDB action: ${action}`);
    }
}

// ============================================================
// REDIS
// ============================================================

async function getRedisClient(config) {
    const key = config.url;
    
    if (connectionCache.redis.has(key)) {
        const cached = connectionCache.redis.get(key);
        if (cached.isOpen) {
            return cached;
        }
        connectionCache.redis.delete(key);
    }
    
    // Lazy load redis
    let redis;
    try {
        redis = require('redis');
    } catch (e) {
        throw new Error('Redis driver not installed. Run: npm install redis');
    }
    
    const client = redis.createClient({
        url: config.url || 'redis://localhost:6379',
        socket: {
            connectTimeout: 10000,
            reconnectStrategy: (retries) => {
                if (retries > 3) return new Error('Max retries reached');
                return Math.min(retries * 100, 3000);
            }
        }
    });
    
    client.on('error', (err) => console.error('[Redis] Error:', err.message));
    
    await client.connect();
    
    connectionCache.redis.set(key, client);
    console.log(`[DB] Redis connected to ${config.url}`);
    
    return client;
}

async function executeRedis(config) {
    const client = await getRedisClient(config);
    
    const action = config.action || 'get';
    const key = config.key || '';
    const value = config.value;
    const ttl = config.ttl || 0;
    
    let result;
    
    switch (action) {
        case 'get':
            result = await client.get(key);
            // Try to parse as JSON
            try {
                result = JSON.parse(result);
            } catch {}
            return result;
            
        case 'set':
            const val = typeof value === 'object' ? JSON.stringify(value) : String(value);
            if (ttl > 0) {
                await client.setEx(key, ttl, val);
            } else {
                await client.set(key, val);
            }
            return 'OK';
            
        case 'del':
            result = await client.del(key);
            return { deleted: result };
            
        case 'hget':
            const field = config.field || value;
            result = await client.hGet(key, field);
            return result;
            
        case 'hset':
            const hfield = config.field;
            const hvalue = typeof value === 'object' ? JSON.stringify(value) : String(value);
            await client.hSet(key, hfield, hvalue);
            return 'OK';
            
        case 'hgetall':
            result = await client.hGetAll(key);
            return result;
            
        case 'lpush':
            const lval = typeof value === 'object' ? JSON.stringify(value) : String(value);
            result = await client.lPush(key, lval);
            return { length: result };
            
        case 'rpush':
            const rval = typeof value === 'object' ? JSON.stringify(value) : String(value);
            result = await client.rPush(key, rval);
            return { length: result };
            
        case 'lrange':
            const start = config.start || 0;
            const stop = config.stop || -1;
            result = await client.lRange(key, start, stop);
            return result;
            
        case 'keys':
            result = await client.keys(key || '*');
            return result;
            
        case 'eval':
            // Lua script execution
            const script = config.script || value;
            const numKeys = config.numKeys || 0;
            const args = config.args || [];
            result = await client.eval(script, { keys: args.slice(0, numKeys), arguments: args.slice(numKeys) });
            return result;
            
        case 'incr':
            result = await client.incr(key);
            return result;
            
        case 'decr':
            result = await client.decr(key);
            return result;
            
        case 'expire':
            await client.expire(key, ttl);
            return 'OK';
            
        case 'ttl':
            result = await client.ttl(key);
            return result;
            
        case 'exists':
            result = await client.exists(key);
            return result === 1;
            
        default:
            throw new Error(`Unknown Redis action: ${action}`);
    }
}

// ============================================================
// IPC HANDLERS
// ============================================================

function registerDatabaseIPC() {
    // PostgreSQL
    ipcMain.handle('db:postgres', async (event, config) => {
        try {
            return await executePostgres(config);
        } catch (e) {
            console.error('[DB] PostgreSQL error:', e.message);
            return { error: e.message, rows: [], rowCount: 0 };
        }
    });
    
    // MySQL
    ipcMain.handle('db:mysql', async (event, config) => {
        try {
            return await executeMysql(config);
        } catch (e) {
            console.error('[DB] MySQL error:', e.message);
            return { error: e.message, rows: [], rowCount: 0 };
        }
    });
    
    // SQLite
    ipcMain.handle('db:sqlite', async (event, config) => {
        try {
            return executeSqlite(config);
        } catch (e) {
            console.error('[DB] SQLite error:', e.message);
            return { error: e.message, rows: [], rowCount: 0 };
        }
    });
    
    // MongoDB
    ipcMain.handle('db:mongodb', async (event, config) => {
        try {
            return await executeMongodb(config);
        } catch (e) {
            console.error('[DB] MongoDB error:', e.message);
            return { error: e.message, documents: [], matchedCount: 0 };
        }
    });
    
    // Redis
    ipcMain.handle('db:redis', async (event, config) => {
        try {
            return await executeRedis(config);
        } catch (e) {
            console.error('[DB] Redis error:', e.message);
            return { error: e.message, result: null };
        }
    });
    
    // Connection test
    ipcMain.handle('db:test', async (event, { type, config }) => {
        try {
            switch (type) {
                case 'postgres':
                    await getPostgresClient(config);
                    break;
                case 'mysql':
                    await getMysqlClient(config);
                    break;
                case 'sqlite':
                    getSqliteClient(config);
                    break;
                case 'mongodb':
                    await getMongoClient(config);
                    break;
                case 'redis':
                    await getRedisClient(config);
                    break;
                default:
                    throw new Error(`Unknown database type: ${type}`);
            }
            return { success: true };
        } catch (e) {
            return { success: false, error: e.message };
        }
    });
    
    // Close all connections
    ipcMain.handle('db:closeAll', async () => {
        return await cleanup();
    });
    
    console.log('[DB] Database IPC handlers registered');
}

// ============================================================
// CLEANUP
// ============================================================

async function cleanup() {
    const closed = [];
    
    for (const [key, pool] of connectionCache.postgres) {
        try { await pool.end(); closed.push(`postgres:${key}`); } catch {}
    }
    connectionCache.postgres.clear();
    
    for (const [key, pool] of connectionCache.mysql) {
        try { await pool.end(); closed.push(`mysql:${key}`); } catch {}
    }
    connectionCache.mysql.clear();
    
    for (const [key, db] of connectionCache.sqlite) {
        try { db.close(); closed.push(`sqlite:${key}`); } catch {}
    }
    connectionCache.sqlite.clear();
    
    for (const [key, client] of connectionCache.mongodb) {
        try { await client.close(); closed.push(`mongodb:${key}`); } catch {}
    }
    connectionCache.mongodb.clear();
    
    for (const [key, client] of connectionCache.redis) {
        try { await client.quit(); closed.push(`redis:${key}`); } catch {}
    }
    connectionCache.redis.clear();
    
    console.log('[DB] Closed connections:', closed);
    return { closed };
}

// ============================================================
// EXPORTS
// ============================================================

module.exports = {
    registerDatabaseIPC,
    cleanup,
    executePostgres,
    executeMysql,
    executeSqlite,
    executeMongodb,
    executeRedis
};
