-- SQLite 3 SQL
-- Main resource records cache table
CREATE TABLE IF NOT EXISTS resource_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_name TEXT NOT NULL,
    record_type INTEGER NOT NULL,
    record_class INTEGER NOT NULL,
    ttl INTEGER NOT NULL,
    rdata BLOB NOT NULL,
    creation_time DATETIME NOT NULL DEFAULT (datetime('now')),
    expiry DATETIME NOT NULL,
    UNIQUE(domain_name, record_type, record_class)
);

-- Negative cache for non-existent domains or record types
CREATE TABLE IF NOT EXISTS negative_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_name TEXT NOT NULL,
    record_type INTEGER NOT NULL,
    record_class INTEGER NOT NULL,
    creation_time DATETIME NOT NULL DEFAULT (datetime('now')),
    expiry DATETIME NOT NULL,
    UNIQUE(domain_name, record_type, record_class)
);

-- Authoritative nameservers for domains
-- Used for iterative resolution
CREATE TABLE IF NOT EXISTS authoritative_nameservers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_name TEXT NOT NULL,
    nameserver TEXT NOT NULL,
    last_used DATETIME NOT NULL DEFAULT (datetime('now')),
    expiry DATETIME NOT NULL DEFAULT (datetime('now', '+7 days')),
    UNIQUE(domain_name, nameserver)
);


CREATE INDEX IF NOT EXISTS idx_rr_domain ON resource_records(domain_name); 
CREATE INDEX IF NOT EXISTS idx_rr_expiry ON resource_records(expiry);
CREATE INDEX IF NOT EXISTS idx_rr_type ON resource_records(record_type);

CREATE INDEX IF NOT EXISTS idx_nc_domain ON negative_cache(domain_name);
CREATE INDEX IF NOT EXISTS idx_nc_expiry ON negative_cache(expiry);

CREATE INDEX IF NOT EXISTS idx_ans_domain ON authoritative_nameservers(domain_name);
CREATE INDEX IF NOT EXISTS idx_ans_expiry ON authoritative_nameservers(expiry);
