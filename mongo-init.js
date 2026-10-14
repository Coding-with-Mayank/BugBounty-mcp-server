// mongo-init.js — runs once when MongoDB container first starts
db = db.getSiblingDB('bugbounty');

db.createCollection('findings');
db.createCollection('scans');
db.createCollection('targets');
db.createCollection('reports');

// Indexes for fast querying
db.findings.createIndex({ target: 1, severity: 1, timestamp: -1 });
db.findings.createIndex({ template_id: 1 });
db.scans.createIndex({ domain: 1, started_at: -1 });
db.targets.createIndex({ domain: 1 }, { unique: true });

print('MongoDB: bugbounty database initialized');
