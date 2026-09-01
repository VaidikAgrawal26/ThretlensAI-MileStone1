# ThreatLens AI — Milestone 1 Final Working Project

This version completes the Milestone 1 scope from the supplied project PDF: architecture/database foundation, authentication, role-based access control, user management, profile management, suspicious-file upload, static analysis, hashing, metadata/file-type detection, PE header/import analysis, printable strings, URL/IP indicators, local signature matching, YARA detection, heuristic risk scoring, scan history and reports.

The supplied PDF explicitly says Milestone 1 should deliver working authentication and file-analysis workflows and static analysis including hashing, metadata extraction and YARA-based detection. Later ML classification, threat monitoring, AI prediction, analytics, Docker/cloud deployment are assigned to later milestones. Keep this project scoped to M1 when presenting it. 

## Roles and demo accounts

| Role | Email | Password |
|---|---|---|
| Administrator | admin@threatlens.local | Admin@123 |
| Security Analyst | analyst@threatlens.local | Analyst@123 |
| SOC Team Member | soc@threatlens.local | Soc@123 |
| Researcher | researcher@threatlens.local | Researcher@123 |

The administrator can create users, change roles, and activate/deactivate accounts. The API enforces the permissions; the frontend also adapts its navigation to the current role.

## Local setup (recommended first)

### 1. PostgreSQL

Install PostgreSQL 18 (or another supported local PostgreSQL version) and make sure the service is running.

Open PowerShell and connect:

    & "C:\Program Files\PostgreSQL\18\bin\psql.exe" -U postgres

Create the project database/user:

    CREATE USER threatlens WITH PASSWORD 'threatlens_dev_password';
    CREATE DATABASE threatlens OWNER threatlens;
    \q

If these already exist, PostgreSQL may report that they already exist; that is safe.

### 2. Backend

From the project root:

    cd backend
    python -m venv venv

Windows PowerShell:

    .\venv\Scripts\Activate.ps1

If PowerShell blocks activation:

    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    .\venv\Scripts\Activate.ps1

Install packages:

    python -m pip install --upgrade pip
    pip install -r requirements.txt

Create configuration:

    Copy-Item .env.example .env

Start API:

    uvicorn app.main:app --reload --port 8000

Check:

    http://localhost:8000/health
    http://localhost:8000/docs

### 3. Frontend

Open a second terminal:

    cd frontend
    npm install
    npm run dev

Open:

    http://localhost:5173

## Docker setup

If Docker Desktop is running, from the project root:

    docker compose up --build

Then open http://localhost:5173.

Stop:

    docker compose down

## Functional Milestone 1 workflow

1. Login as any demo role.
2. Confirm role-specific navigation.
3. Administrator: open User Management, create a user, change a role, activate/deactivate an account.
4. Open Profile and update name/email or change password.
5. Security Analyst/Administrator/Researcher: open File Analysis.
6. Upload a harmless text file. The application never executes uploaded files.
7. The backend calculates MD5/SHA-256, detects file type, extracts strings and indicators, attempts PE analysis, performs local signature matching and YARA matching, computes a static heuristic risk score, and stores the report in PostgreSQL.
8. Open Scan History and click a scan to view its report.
9. Open YARA Rules to see the complete local educational rule library.
10. SOC Team Members can view scan history and reports but cannot run the upload/analyze endpoint.

## Safe test files

Create a harmless file named `clean_sample.txt`:

    This is a harmless ThreatLens AI test file.

Create another harmless text file named `yara_test.txt` with ordinary text containing terms such as:

    powershell
    downloadstring
    invoke-expression
    rundll32.exe
    schtasks

This is not executable malware. It is only test content that demonstrates static string/YARA detection.

## YARA rules

The `backend/yara_rules` directory contains educational rules for:

- PowerShell/execution indicators
- Windows LOLBin indicators
- Persistence indicators
- Credential-access terminology
- Encoded-content indicators
- Network indicators

YARA matching is content-based and static. A match is evidence for review, not proof that a file is malware.

## Database

The backend creates these tables on startup:

- `users`: authentication, profile, role and account status
- `scans`: uploaded-file metadata, hashes, risk/classification and JSON analysis report

Four demo users are automatically seeded on startup if they do not already exist.

## Important scope/security note

This is an educational defensive static-analysis project. Uploaded samples are treated as untrusted data and are never launched or executed. The Milestone 1 risk score is a heuristic/static score, not an ML prediction. Use an isolated malware-analysis lab for real malware research.

## Frontend authentication
The React UI now includes Sign in and Create account flows. Local Milestone 1 signup supports all four project roles for demonstration. In production, administrator/SOC role assignment should be restricted to administrator-controlled provisioning.
