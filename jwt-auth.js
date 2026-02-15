/**
 * JWT Authentication Module for MeshCentral
 * Integrates with PostgreSQL user database for tenant-based authentication
 * 
 * This module validates JWT tokens from the RMM+PSA backend and maps users
 * to MeshCentral's internal user format, enabling true SSO.
 */

'use strict';

module.exports.CreateJWTAuth = function (parent) {
    const obj = {};
    const jwt = require('jsonwebtoken');
    const { Pool } = require('pg');
    
    // JWT configuration
    obj.jwtSecret = process.env.JWT_SECRET;
    obj.agentSignKey = process.env.AGENT_SIGN_KEY;
    
    // PostgreSQL connection pool
    obj.pool = new Pool({
        host: process.env.POSTGRES_HOST || process.env.DB_HOST,
        port: parseInt(process.env.POSTGRES_PORT || process.env.DB_PORT || '25060'),
        database: process.env.POSTGRES_DB || process.env.DB_NAME || 'defaultdb',
        user: process.env.POSTGRES_USER || process.env.DB_USER || 'doadmin',
        password: process.env.POSTGRES_PASSWORD || process.env.DB_PASSWORD,
        ssl: process.env.POSTGRES_SSL === 'true' ? { rejectUnauthorized: false } : false,
        connectionTimeoutMillis: 5000,
        idleTimeoutMillis: 30000,
        max: 10
    });
    
    // User cache to reduce database queries (5 minute TTL)
    obj.userCache = new Map();
    obj.cacheTimeout = 5 * 60 * 1000; // 5 minutes
    
    // Initialize and log configuration
    obj.init = function () {
        parent.debug('jwt-auth', 'JWT Authentication Module Initialized');
        parent.debug('jwt-auth', `PostgreSQL: ${obj.pool.options.host}:${obj.pool.options.port}/${obj.pool.options.database}`);
        
        // Test database connection
        obj.pool.query('SELECT NOW()', (err, result) => {
            if (err) {
                parent.debug('jwt-auth', 'PostgreSQL connection failed:', err.message);
                console.error('❌ JWT Auth: PostgreSQL connection failed:', err.message);
            } else {
                parent.debug('jwt-auth', 'PostgreSQL connection successful');
                console.log('✅ JWT Auth: PostgreSQL connected');
            }
        });
    };
    
    /**
     * Validate JWT token and return decoded payload
     * Tries JWT_SECRET first, then AGENT_SIGN_KEY (for agent tokens)
     */
    obj.verifyToken = function (token, callback) {
        if (!token) return callback(null, null);
        
        // Try JWT_SECRET first (dashboard tokens)
        jwt.verify(token, obj.jwtSecret, (err, decoded) => {
            if (!err) {
                parent.debug('jwt-auth', `Token verified with JWT_SECRET for user: ${decoded.email || decoded.user_id}`);
                return callback(null, decoded);
            }
            
            // Try AGENT_SIGN_KEY (agent tokens)
            if (obj.agentSignKey) {
                jwt.verify(token, obj.agentSignKey, (err2, decoded2) => {
                    if (!err2) {
                        parent.debug('jwt-auth', `Token verified with AGENT_SIGN_KEY for agent: ${decoded2.agent_uuid || decoded2.agentId}`);
                        return callback(null, decoded2);
                    }
                    
                    parent.debug('jwt-auth', 'Token verification failed:', err.message, err2.message);
                    return callback(new Error('Invalid token'), null);
                });
            } else {
                parent.debug('jwt-auth', 'Token verification failed:', err.message);
                return callback(err, null);
            }
        });
    };
    
    /**
     * Validate JWT token and fetch corresponding user from PostgreSQL
     * Returns MeshCentral-formatted user object
     */
    obj.validateToken = function (token, callback) {
        obj.verifyToken(token, (err, decoded) => {
            if (err || !decoded) return callback(null);
            
            // Check cache first
            const cacheKey = `${decoded.email || decoded.user_id}_${decoded.tenant_id || decoded.tenantId}`;
            const cached = obj.userCache.get(cacheKey);
            if (cached && (Date.now() - cached.timestamp < obj.cacheTimeout)) {
                parent.debug('jwt-auth', `Cache hit for user: ${cacheKey}`);
                return callback(cached.user);
            }
            
            // Fetch from database
            const email = decoded.email;
            const tenantId = decoded.tenant_id || decoded.tenantId;
            
            if (!email || !tenantId) {
                parent.debug('jwt-auth', 'Invalid token payload - missing email or tenant_id');
                return callback(null);
            }
            
            obj.getUserByEmail(email, tenantId, (meshUser) => {
                if (meshUser) {
                    // Cache the result
                    obj.userCache.set(cacheKey, {
                        user: meshUser,
                        timestamp: Date.now()
                    });
                }
                callback(meshUser);
            });
        });
    };
    
    /**
     * Fetch user from PostgreSQL and map to MeshCentral user format
     */
    obj.getUserByEmail = async function (email, tenantId, callback) {
        try {
            const result = await obj.pool.query(
                `SELECT 
                    user_id, 
                    email, 
                    name, 
                    role, 
                    tenant_id,
                    created_at,
                    mfa_enabled
                FROM users 
                WHERE email = $1 AND tenant_id = $2 AND deleted_at IS NULL`,
                [email, tenantId]
            );
            
            if (result.rows.length === 0) {
                parent.debug('jwt-auth', `User not found: ${email} in tenant ${tenantId}`);
                return callback(null);
            }
            
            const pgUser = result.rows[0];
            
            // Determine site admin privileges
            // Root tenant (tenant_id = 1 or specific UUID) gets full admin
            // Regular admins get limited admin rights
            let siteadmin = 0;
            if (pgUser.role === 'admin') {
                // Check if root tenant
                if (tenantId === '1' || tenantId === '00000000-0000-0000-0000-000000000001') {
                    siteadmin = 0xFFFFFFFF; // Full admin
                } else {
                    siteadmin = 0x00000006; // Manage users + server update
                }
            }
            
            // Map PostgreSQL user to MeshCentral user format
            const meshUser = {
                _id: `user/${tenantId}/${pgUser.user_id}`,
                email: pgUser.email,
                name: pgUser.name || pgUser.email.split('@')[0],
                domain: tenantId,
                siteadmin: siteadmin,
                emailVerified: true, // Assume emails are verified in your system
                creation: Math.floor(new Date(pgUser.created_at).getTime() / 1000),
                links: {},
                // Custom fields for RMM+PSA integration
                _external: true, // Mark as externally authenticated
                _postgres_user_id: pgUser.user_id,
                _tenant_id: tenantId
            };
            
            parent.debug('jwt-auth', `Mapped user: ${meshUser._id} (${meshUser.email}) siteadmin=${siteadmin}`);
            
            // Fetch device links for this user's tenant
            obj.getUserDeviceLinks(pgUser.user_id, tenantId, (links) => {
                meshUser.links = links;
                callback(meshUser);
            });
            
        } catch (err) {
            parent.debug('jwt-auth', 'PostgreSQL query error:', err.message);
            console.error('❌ JWT Auth: Database query failed:', err.message);
            callback(null);
        }
    };
    
    /**
     * Fetch device links for user's tenant from agents table
     * Returns MeshCentral-compatible device links
     */
    obj.getUserDeviceLinks = async function (userId, tenantId, callback) {
        try {
            const result = await obj.pool.query(
                `SELECT 
                    agent_id,
                    agent_uuid,
                    hostname,
                    meshcentral_nodeid,
                    platform,
                    ip_address,
                    last_seen
                FROM agents 
                WHERE tenant_id = $1 AND meshcentral_nodeid IS NOT NULL`,
                [tenantId]
            );
            
            const links = {};
            const meshId = `mesh/${tenantId}/default`; // Default mesh for tenant
            
            result.rows.forEach(agent => {
                if (agent.meshcentral_nodeid) {
                    // Link user to device
                    links[agent.meshcentral_nodeid] = { rights: 0xFFFFFFFF }; // Full rights
                    
                    // Link to mesh
                    if (!links[meshId]) {
                        links[meshId] = { rights: 0xFFFFFFFF }; // Full rights to mesh
                    }
                }
            });
            
            parent.debug('jwt-auth', `Found ${result.rows.length} devices for tenant ${tenantId}`);
            callback(links);
            
        } catch (err) {
            parent.debug('jwt-auth', 'Failed to fetch device links:', err.message);
            callback({});
        }
    };
    
    /**
     * Ensure tenant mesh exists, create if not
     * Each tenant gets their own device group
     */
    obj.ensureTenantMesh = function (tenantId, callback) {
        const meshId = `mesh/${tenantId}/default`;
        
        parent.db.Get(meshId, function (err, meshes) {
            if (meshes && meshes.length > 0) {
                parent.debug('jwt-auth', `Mesh exists: ${meshId}`);
                return callback(meshes[0]);
            }
            
            // Create new mesh for tenant
            const newMesh = {
                _id: meshId,
                name: `Tenant ${tenantId} Devices`,
                mtype: 2, // Managed mesh
                desc: `Auto-created device group for tenant ${tenantId}`,
                domain: tenantId,
                flags: 0,
                links: {}
            };
            
            parent.db.Set(newMesh);
            parent.debug('jwt-auth', `Created mesh: ${meshId}`);
            console.log(`✅ JWT Auth: Created mesh for tenant ${tenantId}`);
            
            callback(newMesh);
        });
    };
    
    /**
     * Clear user cache (useful for debugging or after user updates)
     */
    obj.clearCache = function (email, tenantId) {
        if (email && tenantId) {
            const cacheKey = `${email}_${tenantId}`;
            obj.userCache.delete(cacheKey);
            parent.debug('jwt-auth', `Cleared cache for ${cacheKey}`);
        } else {
            obj.userCache.clear();
            parent.debug('jwt-auth', 'Cleared entire user cache');
        }
    };
    
    /**
     * Extract JWT token from various sources
     * Checks: Authorization header, query parameter, cookie
     */
    obj.extractToken = function (req) {
        // Check Authorization header (Bearer token)
        if (req.headers && req.headers.authorization) {
            const parts = req.headers.authorization.split(' ');
            if (parts.length === 2 && parts[0] === 'Bearer') {
                return parts[1];
            }
        }
        
        // Check query parameter
        if (req.query && req.query.token) {
            return req.query.token;
        }
        
        // Check cookie (from WebSocket upgrade request)
        if (req.headers && req.headers.cookie) {
            const cookies = req.headers.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.startsWith('jwt=')) {
                    return cookie.substring(4);
                }
            }
        }
        
        return null;
    };
    
    /**
     * Health check
     */
    obj.healthCheck = async function (callback) {
        try {
            const result = await obj.pool.query('SELECT NOW() as time, COUNT(*) as user_count FROM users WHERE deleted_at IS NULL');
            callback({
                status: 'healthy',
                database: 'connected',
                users: result.rows[0].user_count,
                cache_size: obj.userCache.size,
                timestamp: result.rows[0].time
            });
        } catch (err) {
            callback({
                status: 'unhealthy',
                database: 'disconnected',
                error: err.message
            });
        }
    };
    
    // Initialize on creation
    obj.init();
    
    return obj;
};
