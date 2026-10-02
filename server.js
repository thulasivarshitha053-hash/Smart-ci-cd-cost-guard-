const express = require('express');
const crypto = require('crypto');
const https = require('https');
const db = require('./db');
require('dotenv').config();

const app = express();

// Capture raw body safely for exact cryptographic signature match
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

const PORT = process.env.PORT || 3000;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;
const SLACK_WEBHOOK_URL = process.env.SLACK_WEBHOOK_URL;

// GitHub Actions Official Pricing Matrix ($/minute)
const RUNNER_RATES = {
  ubuntu: 0.008,
  windows: 0.016,
  macos: 0.08,
  selfHosted: 0.0,
  default: 0.008
};

/**
 * 1. Cryptographic Signature Verification (HMAC-SHA256)
 * Fixed: Buffer length check to prevent runtime error crash
 */
function verifySignature(req) {
  const signature = req.headers['x-hub-signature-256'];
  if (!signature || !req.rawBody) return false;

  const hmac = crypto.createHmac('sha256', WEBHOOK_SECRET);
  const digest = 'sha256=' + hmac.update(req.rawBody).digest('hex');

  const sigBuffer = Buffer.from(signature);
  const digestBuffer = Buffer.from(digest);

  // Buffer lengths must match for timingSafeEqual
  if (sigBuffer.length !== digestBuffer.length) return false;

  return crypto.timingSafeEqual(sigBuffer, digestBuffer);
}

/**
 * 2. Dynamic Pricing Calculator Logic
 */
function calculateRunnerRate(labels = []) {
  const labelString = labels.join(' ').toLowerCase();

  if (labelString.includes('self-hosted')) return RUNNER_RATES.selfHosted;
  if (labelString.includes('macos')) return RUNNER_RATES.macos;
  if (labelString.includes('windows')) return RUNNER_RATES.windows;
  
  return RUNNER_RATES.ubuntu;
}

/**
 * 3. Robust Slack Webhook Dispatcher
 */
function sendSlackAlert(repoName, jobName, durationMins, wastedCost) {
  if (!SLACK_WEBHOOK_URL || SLACK_WEBHOOK_URL.includes('YOUR/SLACK')) return;

  const payload = JSON.stringify({
    text: `⚠️ *CI/CD Build Failure Alert!*`,
    attachments: [
      {
        color: '#FF0000',
        fields: [
          { title: 'Repository', value: repoName, short: true },
          { title: 'Job Name', value: jobName, short: true },
          { title: 'Duration Wasted', value: `${durationMins} mins`, short: true },
          { title: 'Estimated Loss', value: `$${wastedCost}`, short: true }
        ]
      }
    ]
  });

  const url = new URL(SLACK_WEBHOOK_URL);
  const options = {
    hostname: url.hostname,
    path: url.pathname,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload)
    }
  };

  const req = https.request(options, (res) => {
    if (res.statusCode !== 200) {
      console.error(`Slack Notification failed with status code: ${res.statusCode}`);
    }
  });

  req.on('error', (e) => console.error('Slack Request Error:', e.message));
  req.write(payload);
  req.end();
}

/**
 * 4. Main Webhook Handler Endpoint
 */
app.post('/api/v1/webhook', async (req, res) => {
  // Security Check
  if (!verifySignature(req)) {
    console.warn('⚠️ Rejected unauthorized request: HMAC Signature Mismatch.');
    return res.status(401).json({ error: 'Invalid HMAC Signature' });
  }

  const event = req.headers['x-github-event'];

  if (event === 'workflow_job') {
    const { action, workflow_job, repository } = req.body;

    // Process only completed failing jobs
    if (action === 'completed' && workflow_job.conclusion === 'failure') {
      const startTime = new Date(workflow_job.started_at);
      const endTime = new Date(workflow_job.completed_at);
      
      // Fixed: GitHub charges full minute for partial minutes (Math.ceil)
      const durationMs = endTime - startTime;
      const durationMins = Math.max(1, Math.ceil(durationMs / (1000 * 60)));

      // OS-based pricing calculation
      const labels = workflow_job.labels || [];
      const ratePerMin = calculateRunnerRate(labels);
      const wastedCost = parseFloat((durationMins * ratePerMin).toFixed(4));
      const runnerOS = labels.length > 0 ? labels.join(',') : 'ubuntu';

      try {
        // Save to Database (PostgreSQL / Supabase)
        const insertQuery = `
          INSERT INTO cost_logs (job_id, repo_name, job_name, runner_os, duration_mins, wasted_cost)
          VALUES ($1, $2, $3, $4, $5, $6)
          ON CONFLICT (job_id) DO NOTHING;
        `;
        await db.query(insertQuery, [
          workflow_job.id,
          repository.name,
          workflow_job.name,
          runnerOS,
          durationMins,
          wastedCost
        ]);

        console.log(`🚨 Logged Failure | Repo: ${repository.name} | Loss: $${wastedCost}`);

        // Dispatch Instant Alert
        sendSlackAlert(repository.name, workflow_job.name, durationMins, wastedCost);

      } catch (dbErr) {
        console.error('❌ Error saving metric to Database:', dbErr.message);
      }
    }
  }

  return res.status(200).json({ status: 'Event Processed' });
});

/**
 * 5. Analytics Endpoint for Dashboard UI
 */
app.get('/api/v1/analytics', async (req, res) => {
  try {
    const totalQuery = `
      SELECT 
        COUNT(*) as total_failures,
        COALESCE(SUM(wasted_cost), 0) as total_wasted_cost
      FROM cost_logs;
    `;
    const logsQuery = `SELECT * FROM cost_logs ORDER BY created_at DESC LIMIT 50;`;

    const totalResult = await db.query(totalQuery);
    const logsResult = await db.query(logsQuery);

    res.status(200).json({
      summary: {
        totalFailures: parseInt(totalResult.rows[0].total_failures),
        totalWastedCost: parseFloat(totalResult.rows[0].total_wasted_cost)
      },
      logs: logsResult.rows
    });
  } catch (err) {
    console.error('❌ Analytics Fetch Error:', err.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Smart CI/CD Cost Guard running on port ${PORT}`);
});
 // GET API: Dashboard lo cost logs chupinchadaniki
app.get('/api/costs', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('cost_logs')
            .select('*')
            .order('created_at', { ascending: false });

        if (error) throw error;
        res.json({ success: true, data });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// GET API: Monthly Analytics & Total Spending Graph kosam
app.get('/api/analytics', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('cost_logs')
            .select('estimated_cost, created_at, repo_name');

        if (error) throw error;

        // Total spending calculation
        const totalCost = data.reduce((sum, item) => sum + Number(item.estimated_cost || 0), 0);

        res.json({
            success: true,
            total_runs: data.length,
            total_cost: totalCost.toFixed(4),
            logs: data
        });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});
const express = require('express');
const crypto = require('crypto');
const supabase = require('./db'); // db.js నుండి Supabase client import

const app = express();
app.use(express.json());

// 1. API Key Authentication Middleware
const authenticateApiKey = async (req, res, next) => {
    const apiKey = req.headers['x-api-key'];

    if (!apiKey) {
        return res.status(401).json({ error: 'Unauthorized: Missing API Key' });
    }

    // SHA-256 Hash conversion
    const keyHash = crypto.createHash('sha256').update(apiKey).digest('hex');

    const { data: keyData, error } = await supabase
        .from('api_keys')
        .select('org_id, is_active')
        .eq('key_hash', keyHash)
        .single();

    if (error || !keyData || !keyData.is_active) {
        return res.status(403).json({ error: 'Forbidden: Invalid or Inactive API Key' });
    }

    req.org_id = keyData.org_id;
    next();
};

// 2. Enterprise Cost Ingestion Endpoint
app.post('/api/v1/enterprise/costs', authenticateApiKey, async (req, res) => {
    const { repo_name, workflow_name, run_id, duration_seconds, estimated_cost } = req.body;

    const { data, error } = await supabase
        .from('enterprise_cost_logs')
        .insert([
            {
                org_id: req.org_id,
                repo_name,
                workflow_name,
                run_id,
                duration_seconds,
                estimated_cost
            }
        ]);

    if (error) {
        return res.status(500).json({ error: error.message });
    }

    res.status(200).json({ status: 'success', message: 'Enterprise cost logged successfully!' });
});

// 3. Health Check
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'healthy', service: 'cost-guard-backend' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

