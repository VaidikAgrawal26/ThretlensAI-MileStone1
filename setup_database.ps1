$ErrorActionPreference = 'Stop'
$psql = "C:\Program Files\PostgreSQL\18\bin\psql.exe"
if (-not (Test-Path $psql)) { throw "PostgreSQL 18 psql.exe was not found at $psql. Update the path if your PostgreSQL version is different." }
Write-Host "Connecting as postgres. Enter your PostgreSQL administrator password when prompted."
& $psql -U postgres -c "CREATE USER threatlens WITH PASSWORD 'threatlens_dev_password';"
if ($LASTEXITCODE -ne 0) { Write-Host "The user may already exist; continuing." }
& $psql -U postgres -c "CREATE DATABASE threatlens OWNER threatlens;"
if ($LASTEXITCODE -ne 0) { Write-Host "The database may already exist; continuing." }
Write-Host "Database setup attempted. Start the backend next."
