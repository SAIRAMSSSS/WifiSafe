const { getDatabase } = require('../database/init');
const { v4: uuidv4 } = require('uuid');

// Log audit event
const logAudit = (userId, action, resourceType, resourceId, details, req) => {
  try {
    const db = getDatabase();
    db.prepare(`
      INSERT INTO audit_logs (id, user_id, action, resource_type, resource_id, details, ip_address, user_agent)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      uuidv4(),
      userId,
      action,
      resourceType,
      resourceId,
      typeof details === 'object' ? JSON.stringify(details) : details,
      req?.ip || req?.connection?.remoteAddress || 'unknown',
      req?.headers?.['user-agent'] || 'unknown'
    );
  } catch (error) {
    console.error('Audit log error:', error);
  }
};

// Audit middleware for automatic logging
const auditMiddleware = (action, resourceType) => {
  return (req, res, next) => {
    const originalJson = res.json;
    
    res.json = function(data) {
      // Log after successful response
      if (res.statusCode >= 200 && res.statusCode < 300) {
        const resourceId = req.params.id || data?.id || null;
        logAudit(
          req.user?.id || 'anonymous',
          action,
          resourceType,
          resourceId,
          { method: req.method, path: req.path, body: req.body },
          req
        );
      }
      return originalJson.call(this, data);
    };
    
    next();
  };
};

module.exports = { logAudit, auditMiddleware };
