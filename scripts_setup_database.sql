-- ThreatLens AI local PostgreSQL setup (development only)
-- Run while connected as the PostgreSQL administrator (usually postgres).
CREATE USER threatlens WITH PASSWORD 'threatlens_dev_password';
CREATE DATABASE threatlens OWNER threatlens;
