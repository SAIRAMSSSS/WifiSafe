/**
 * Email Service for sending alert notifications
 * Uses nodemailer for SMTP email delivery
 */

const logger = require('../utils/logger');

// Configuration from environment variables
const SMTP_CONFIG = {
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
        user: process.env.SMTP_USER || '',
        pass: process.env.SMTP_PASS || ''
    }
};

const FROM_EMAIL = process.env.SMTP_FROM || 'Black Codex <alerts@blackcodex.local>';

// Track if nodemailer is available
let nodemailer = null;
let transporter = null;

try {
    nodemailer = require('nodemailer');
    if (SMTP_CONFIG.auth.user && SMTP_CONFIG.auth.pass) {
        transporter = nodemailer.createTransport(SMTP_CONFIG);
        logger.info('[Email] SMTP transporter configured');
    } else {
        logger.warn('[Email] SMTP credentials not configured - emails will be logged only');
    }
} catch (e) {
    logger.warn('[Email] nodemailer not installed - emails will be logged only');
}

/**
 * Send a critical vulnerability alert email
 * @param {string} email - Recipient email address
 * @param {object} alertDetails - Alert information
 */
async function sendCriticalAlert(email, alertDetails) {
    if (!email) {
        logger.debug('[Email] No email configured, skipping alert');
        return { success: false, reason: 'No email configured' };
    }

    const { title, severity, description, deviceIp, deviceName, timestamp, type } = alertDetails;

    const subject = `🚨 [${severity.toUpperCase()}] ${title} - Black Codex Alert`;

    const htmlContent = `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; background: #0a0a0f; color: #e5e5e5; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: #1a1a2e; border-radius: 8px; overflow: hidden; border: 1px solid #333; }
        .header { background: linear-gradient(135deg, #00ff88, #00d4ff); padding: 20px; text-align: center; }
        .header h1 { color: #0a0a0f; margin: 0; font-size: 24px; }
        .content { padding: 30px; }
        .alert-badge { display: inline-block; padding: 8px 16px; border-radius: 4px; font-weight: bold; text-transform: uppercase; margin-bottom: 20px; }
        .critical { background: #ff3b3b; color: white; }
        .high { background: #ff8c00; color: white; }
        .medium { background: #ffd700; color: #0a0a0f; }
        .info-row { margin: 10px 0; padding: 10px; background: #0a0a0f; border-radius: 4px; }
        .label { color: #888; font-size: 12px; text-transform: uppercase; }
        .value { color: #00ff88; font-family: monospace; }
        .footer { padding: 20px; text-align: center; border-top: 1px solid #333; color: #666; font-size: 12px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>⚡ Black Codex Security Alert</h1>
        </div>
        <div class="content">
          <span class="alert-badge ${severity}">${severity.toUpperCase()} SEVERITY</span>
          <h2 style="color: #fff; margin-bottom: 20px;">${title}</h2>
          <p style="color: #ccc; line-height: 1.6;">${description}</p>
          
          <div class="info-row">
            <div class="label">Alert Type</div>
            <div class="value">${type || 'Security Alert'}</div>
          </div>
          <div class="info-row">
            <div class="label">Device</div>
            <div class="value">${deviceName || 'Unknown'} (${deviceIp || 'N/A'})</div>
          </div>
          <div class="info-row">
            <div class="label">Timestamp</div>
            <div class="value">${new Date(timestamp).toLocaleString()}</div>
          </div>
          
          <div style="margin-top: 30px; padding: 15px; background: #ff3b3b22; border: 1px solid #ff3b3b55; border-radius: 4px;">
            <strong style="color: #ff3b3b;">⚠️ Immediate Action Required</strong>
            <p style="margin: 10px 0 0; color: #ccc; font-size: 14px;">
              Please review this alert in your Black Codex dashboard immediately and take appropriate action.
            </p>
          </div>
        </div>
        <div class="footer">
          Black Codex Cyber-Defense Platform • Automated Security Alert
        </div>
      </div>
    </body>
    </html>
  `;

    const textContent = `
BLACK CODEX SECURITY ALERT
==========================

Severity: ${severity.toUpperCase()}
Alert: ${title}

${description}

Device: ${deviceName || 'Unknown'} (${deviceIp || 'N/A'})
Type: ${type || 'Security Alert'}
Time: ${new Date(timestamp).toLocaleString()}

⚠️ IMMEDIATE ACTION REQUIRED
Please review this alert in your Black Codex dashboard.
  `;

    // If transporter is available, send real email
    if (transporter) {
        try {
            const result = await transporter.sendMail({
                from: FROM_EMAIL,
                to: email,
                subject,
                text: textContent,
                html: htmlContent
            });
            logger.info(`[Email] Alert sent to ${email}: ${result.messageId}`);
            return { success: true, messageId: result.messageId };
        } catch (error) {
            logger.error(`[Email] Failed to send alert: ${error.message}`);
            return { success: false, reason: error.message };
        }
    } else {
        // Log the email for development/testing
        logger.info(`[Email] SIMULATED - Would send to: ${email}`);
        logger.info(`[Email] Subject: ${subject}`);
        logger.debug(`[Email] Content: ${textContent.substring(0, 200)}...`);
        return { success: true, simulated: true };
    }
}

/**
 * Test email connection
 * @param {string} email - Test recipient email
 */
async function testEmailConnection(email) {
    if (!transporter) {
        return {
            success: false,
            reason: 'SMTP not configured. Set SMTP_HOST, SMTP_USER, and SMTP_PASS environment variables.'
        };
    }

    try {
        await transporter.verify();

        // Send a test email
        const result = await transporter.sendMail({
            from: FROM_EMAIL,
            to: email,
            subject: '✅ Black Codex - Email Test Successful',
            text: 'This is a test email from Black Codex. Your email alerts are configured correctly!',
            html: `
        <div style="font-family: Arial, sans-serif; padding: 20px; background: #0a0a0f; color: #e5e5e5;">
          <h2 style="color: #00ff88;">✅ Email Test Successful</h2>
          <p>Your Black Codex email alerts are configured correctly.</p>
          <p>You will receive notifications when critical or high-severity vulnerabilities are detected.</p>
        </div>
      `
        });

        return { success: true, messageId: result.messageId };
    } catch (error) {
        return { success: false, reason: error.message };
    }
}

/**
 * Get alert email from settings
 * @param {object} db - Database connection
 */
function getAlertEmail(db) {
    try {
        const setting = db.prepare('SELECT value FROM settings WHERE key = ?').get('alert_email');
        return setting ? setting.value : null;
    } catch (e) {
        return null;
    }
}

/**
 * Save alert email to settings
 * @param {object} db - Database connection
 * @param {string} email - Email address to save
 */
function saveAlertEmail(db, email) {
    const now = new Date().toISOString();
    const existing = db.prepare('SELECT * FROM settings WHERE key = ?').get('alert_email');

    if (existing) {
        db.prepare('UPDATE settings SET value = ?, updated_at = ? WHERE key = ?')
            .run(email, now, 'alert_email');
    } else {
        db.prepare('INSERT INTO settings (key, value, category, updated_at, created_at) VALUES (?, ?, ?, ?, ?)')
            .run('alert_email', email, 'notifications', now, now);
    }

    return { success: true, email };
}

module.exports = {
    sendCriticalAlert,
    testEmailConnection,
    getAlertEmail,
    saveAlertEmail,
    isConfigured: () => !!transporter
};
