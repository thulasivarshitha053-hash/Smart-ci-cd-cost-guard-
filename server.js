const express = require('express');
const crypto = require('crypto');
const supabase = require('./db');

const app = express();
app.use(express.json());

// 1. API Key Authentication Middleware
const authenticateApiKey = async (req, res, next) => {
    const apiKey = req.headers['x-api-key'];

    if (!apiKey) {
        return res.status(401).json({ error: 'Unauthorized: Missing API Key' });
    }

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

// 3. Health Check Endpoint
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'healthy', service: 'cost-guard-backend' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

