import { useEffect, useMemo, useState } from 'react';
import { api } from './api';

const ROLE_LABELS = {
  administrator: 'Administrator',
  security_analyst: 'Security Analyst',
  soc_member: 'SOC Team Member',
  researcher: 'Researcher',
};

const ROLE_META = {
  administrator: {
    short: 'ADMIN',
    description: 'Manage users, platform access and security operations.',
    accent: 'purple',
    permissions: ['Manage users & roles', 'Configure platform settings', 'Access all dashboards & reports', 'Monitor platform activity'],
  },
  security_analyst: {
    short: 'ANALYST',
    description: 'Investigate suspicious files using static analysis.',
    accent: 'blue',
    permissions: ['Upload suspicious files', 'Run static analysis', 'Review analysis reports', 'Review security alerts'],
  },
  soc_member: {
    short: 'SOC',
    description: 'Monitor detections, incidents and security activity.',
    accent: 'orange',
    permissions: ['Monitor detection logs', 'View active threats', 'Track malware incidents', 'Review alert history'],
  },
  researcher: {
    short: 'RESEARCH',
    description: 'Research malware samples and historical analysis results.',
    accent: 'green',
    permissions: ['Upload research samples', 'Analyze malware families', 'Review results', 'Access historical analytics'],
  },
};

function RiskBadge({ score, label }) {
  const cls = score >= 75 ? 'danger' : score >= 40 ? 'warning' : 'safe';
  return <span className={`badge ${cls}`}>{score}/100 · {label}</span>;
}

function Logo() {
  return <div className="logo-mark"><span>TL</span><i /></div>;
}

function Auth({ onLogin }) {
  const [mode, setMode] = useState('login');
  const [form, setForm] = useState({ email: 'analyst@threatlens.local', password: 'Analyst@123', full_name: '', role: 'researcher' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  function update(key, value) { setForm(prev => ({ ...prev, [key]: value })); }

  async function submit(e) {
    e.preventDefault(); setError(''); setLoading(true);
    try {
      const endpoint = mode === 'login' ? '/api/auth/login' : '/api/auth/register';
      const body = mode === 'login'
        ? { email: form.email, password: form.password }
        : { email: form.email, password: form.password, full_name: form.full_name, role: form.role };
      const data = await api(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      if (mode === 'login') {
        localStorage.setItem('threatlens_token', data.access_token);
        onLogin(data.user);
      } else {
        setMode('login');
        setForm(prev => ({ ...prev, password: '' }));
        setError('Account created. Sign in with your new credentials.');
      }
    } catch (err) { setError(err.message); }
    finally { setLoading(false); }
  }

  const isLogin = mode === 'login';
  return (
    <div className="auth-page">
      <div className="auth-backdrop"><div className="orb orb-a"/><div className="orb orb-b"/></div>
      <div className="auth-layout">
        <section className="auth-branding">
          <div className="brand-row"><Logo/><div><strong>ThreatLens <em>AI</em></strong><span>Security Intelligence Platform</span></div></div>
          <div className="branding-copy">
            <p className="eyebrow">MILESTONE 01 · STATIC ANALYSIS</p>
            <h1>See the threat<br/><span>before it runs.</span></h1>
            <p>Analyze suspicious files safely using hashes, metadata, PE inspection, indicators, signatures and YARA rules — without executing the sample.</p>
          </div>
          <div className="security-points"><span>● Static-only analysis</span><span>● JWT authentication</span><span>● Role-based access</span></div>
        </section>
        <section className="auth-card">
          <div className="auth-tabs"><button className={isLogin ? 'selected' : ''} onClick={() => {setMode('login');setError('')}}>Sign in</button><button className={!isLogin ? 'selected' : ''} onClick={() => {setMode('signup');setError('')}}>Create account</button></div>
          <div className="auth-heading"><p className="eyebrow">{isLogin ? 'WELCOME BACK' : 'NEW ACCOUNT'}</p><h2>{isLogin ? 'Sign in to ThreatLens' : 'Create your analyst profile'}</h2><p>{isLogin ? 'Use your security role credentials to enter the workspace.' : 'Choose a role for local Milestone 1 demonstration.'}</p></div>
          <form onSubmit={submit} className="auth-form">
            {!isLogin && <label>Full name<input required minLength="2" value={form.full_name} onChange={e => update('full_name', e.target.value)} placeholder="e.g. Priya Sharma"/></label>}
            <label>Email address<input required type="email" value={form.email} onChange={e => update('email', e.target.value)} placeholder="you@company.com"/></label>
            <label>Password<input required type="password" minLength="8" value={form.password} onChange={e => update('password', e.target.value)} placeholder="Minimum 8 characters"/></label>
            {!isLogin && <label>Security role<select value={form.role} onChange={e => update('role', e.target.value)}>{Object.entries(ROLE_LABELS).map(([value,label]) => <option key={value} value={value}>{label}</option>)}</select></label>}
            {error && <div className={error.startsWith('Account created') ? 'success' : 'error'}>{error}</div>}
            <button className="primary auth-submit" disabled={loading}>{loading ? 'Please wait…' : isLogin ? 'Enter secure workspace →' : 'Create account →'}</button>
          </form>
          {isLogin && <div className="demo-accounts"><div className="demo-title">DEMO ACCOUNTS</div><div className="demo-grid"><button onClick={() => setForm({ ...form, email: 'admin@threatlens.local', password: 'Admin@123' })}><b>Admin</b><small>Administrator</small></button><button onClick={() => setForm({ ...form, email: 'analyst@threatlens.local', password: 'Analyst@123' })}><b>Analyst</b><small>Security Analyst</small></button><button onClick={() => setForm({ ...form, email: 'soc@threatlens.local', password: 'Soc@123' })}><b>SOC</b><small>SOC Member</small></button><button onClick={() => setForm({ ...form, email: 'researcher@threatlens.local', password: 'Researcher@123' })}><b>Research</b><small>Researcher</small></button></div></div>}
          {!isLogin && <p className="auth-note">Local project mode: role selection is enabled for demonstrating RBAC. In a production deployment, privileged roles should be assigned by an administrator.</p>}
        </section>
      </div>
    </div>
  );
}

function Layout({ user, onLogout, active, setActive, children }) {
  const items = useMemo(() => {
    const common = [['overview','Overview','⌂'], ['history','Scan History','◷'], ['rules','YARA Rules','◈'], ['profile','Profile','○']];
    if (user.role === 'administrator') return [['overview','Overview','⌂'], ['users','User Management','♙'], ['analysis','File Analysis','⌁'], ...common.slice(1)];
    if (user.role === 'soc_member') return [['overview','Overview','⌂'], ['history','Detection Logs','◷'], ['rules','YARA Rules','◈'], ['profile','Profile','○']];
    return [['overview','Overview','⌂'], ['analysis','File Analysis','⌁'], ['history','Scan History','◷'], ['rules','YARA Rules','◈'], ['profile','Profile','○']];
  }, [user.role]);
  return <div className="app"><header className="topbar"><div className="brand-row"><Logo/><div><strong>ThreatLens <em>AI</em></strong><span>Security Intelligence Platform</span></div></div><div className="top-user"><div className="avatar">{user.full_name.slice(0,1).toUpperCase()}</div><div><b>{user.full_name}</b><small>{ROLE_LABELS[user.role]}</small></div><button className="logout" onClick={onLogout}>Sign out</button></div></header><div className="workspace"><aside className="sidebar"><div className="side-label">WORKSPACE</div>{items.map(([id,label,icon]) => <button key={id} className={active === id ? 'nav-active' : ''} onClick={() => setActive(id)}><span className="nav-icon">{icon}</span>{label}</button>)}<div className="sidebar-bottom"><div className="role-mini"><span className={`role-dot ${ROLE_META[user.role].accent}`}/><div><b>{ROLE_LABELS[user.role]}</b><small>Access level active</small></div></div></div></aside><main>{children}</main></div></div>;
}

function Overview({ user, setActive }) {
  const [stats, setStats] = useState(null), [history, setHistory] = useState([]);
  useEffect(() => { api('/api/scans').then(setHistory).catch(() => {}); if (user.role === 'administrator') api('/api/users/stats/summary').then(setStats).catch(() => {}); }, [user]);
  const role = ROLE_META[user.role];
  const counts = { total: history.length, malware: history.filter(x => x.classification === 'Potential Malware').length, suspicious: history.filter(x => x.classification === 'Suspicious').length, clean: history.filter(x => x.classification === 'No Strong Indicators').length };
  return <>
    <div className="page-head"><div><p className="eyebrow">SECURITY OVERVIEW</p><h1>Good morning, {user.full_name.split(' ')[0]}.</h1><p>Welcome to your {ROLE_LABELS[user.role].toLowerCase()} workspace.</p></div><span className={`role-chip ${role.accent}`}>{role.short} ACCESS</span></div>
    <section className={`role-hero ${role.accent}`}><div className="role-icon">{user.role === 'administrator' ? '♙' : user.role === 'soc_member' ? '◉' : user.role === 'researcher' ? '⌬' : '⌁'}</div><div><p className="eyebrow">YOUR SECURITY ROLE</p><h2>{ROLE_LABELS[user.role]}</h2><p>{role.description}</p></div><button onClick={() => setActive(user.role === 'administrator' ? 'users' : user.role === 'soc_member' ? 'history' : 'analysis')} className="primary">Open workspace →</button></section>
    <div className="metric-grid">{user.role === 'administrator' && stats ? <><Metric n={stats.total_users} l="Total users"/><Metric n={stats.active_users} l="Active accounts"/><Metric n={stats.total_scans} l="Total scans"/><Metric n={stats.potential_malware_scans} l="Potential malware"/></> : <><Metric n={counts.total} l={user.role === 'soc_member' ? 'Detection records' : 'Your scans'}/><Metric n={counts.malware} l="Potential malware"/><Metric n={counts.suspicious} l="Suspicious"/><Metric n={counts.clean} l="No strong indicators"/></>}</div>
    <div className="dashboard-grid"><section className="panel"><div className="panel-head"><div><p className="eyebrow">ACCESS CONTROL</p><h3>What you can do</h3></div><span className="live-dot">● Active</span></div><div className="permission-list">{role.permissions.map((x,i) => <div key={x}><span>{String(i+1).padStart(2,'0')}</span><b>{x}</b><i>✓</i></div>)}</div></section><section className="panel"><div className="panel-head"><div><p className="eyebrow">QUICK ACTIONS</p><h3>Security operations</h3></div></div><div className="quick-grid">{user.role === 'administrator' && <Action title="Manage users" desc="Roles & account status" icon="♙" onClick={() => setActive('users')}/>} {user.role !== 'soc_member' && <Action title="Analyze file" desc="Static-only scan" icon="⌁" onClick={() => setActive('analysis')}/>}<Action title={user.role === 'soc_member' ? 'Detection logs' : 'Scan history'} desc="Review previous scans" icon="◷" onClick={() => setActive('history')}/><Action title="YARA library" desc="Review detection rules" icon="◈" onClick={() => setActive('rules')}/></div></section></div>
  </>;
}
function Metric({ n, l }) { return <div className="metric-card"><span>{l}</span><strong>{n}</strong><small>Milestone 1</small></div>; }
function Action({ title, desc, icon, onClick }) { return <button className="action-card" onClick={onClick}><span className="action-icon">{icon}</span><span><b>{title}</b><small>{desc}</small></span><i>→</i></button>; }

function Analysis({ onScan }) { const [file,setFile]=useState(null),[loading,setLoading]=useState(false),[error,setError]=useState(''); async function submit(e){e.preventDefault();if(!file){setError('Choose a file first.');return}setLoading(true);setError('');try{const fd=new FormData();fd.append('file',file);onScan(await api('/api/scans/analyze',{method:'POST',body:fd}))}catch(err){setError(err.message)}finally{setLoading(false)}} return <><div className="page-head"><div><p className="eyebrow">STATIC ANALYSIS</p><h1>Analyze a suspicious file</h1><p>Files are inspected without execution.</p></div><span className="pill">MAX 20 MB</span></div><section className="panel analysis-panel"><div className="scan-banner"><div><b>Safe static workflow</b><span>Hash → metadata → PE → indicators → signatures → YARA</span></div><span className="safe-label">● NO EXECUTION</span></div><form onSubmit={submit}><label className="file-drop"><input type="file" onChange={e=>setFile(e.target.files[0]||null)}/><span className="upload-icon">↑</span><b>{file ? file.name : 'Choose a file to analyze'}</b><small>{file ? `${(file.size/1024).toFixed(1)} KB selected` : 'TXT, PDF, EXE, DLL and other files up to 20 MB'}</small></label>{error&&<div className="error">{error}</div>}<button className="primary scan-button" disabled={loading}>{loading?'Analyzing file…':'Run static analysis →'}</button></form><div className="analysis-flow">{['MD5 / SHA-256','Metadata','PE headers','Strings','URLs / IPs','Signatures','YARA'].map(x=><span key={x}>{x}</span>)}</div></section></> }

function History({ onOpen }) { const [rows,setRows]=useState([]),[loading,setLoading]=useState(true),[error,setError]=useState(''); async function load(){setLoading(true);try{setRows(await api('/api/scans'))}catch(e){setError(e.message)}finally{setLoading(false)}} useEffect(()=>{load()},[]); return <><div className="page-head"><div><p className="eyebrow">DETECTION RECORDS</p><h1>Scan history</h1><p>Review static-analysis results available to your role.</p></div><button onClick={load}>↻ Refresh</button></div><section className="panel">{error&&<div className="error">{error}</div>}{loading?<p className="muted">Loading detection records…</p>:rows.length===0?<div className="empty"><span>◷</span><b>No scans yet</b><small>Run a static analysis to create the first record.</small></div>:<div className="table-wrap"><table><thead><tr><th>File</th><th>Risk</th><th>Analyst</th><th>Type</th><th>SHA-256</th><th>Time</th></tr></thead><tbody>{rows.map(s=><tr key={s.id} onClick={()=>onOpen(s.id)}><td><b>{s.original_filename}</b></td><td><RiskBadge score={s.risk_score} label={s.classification}/></td><td>{s.analyst_name}</td><td>{s.file_type}</td><td className="mono">{s.sha256.slice(0,18)}…</td><td>{new Date(s.created_at).toLocaleString()}</td></tr>)}</tbody></table></div>}</section></> }

function Report({ scan }) { if(!scan) return <section className="panel empty"><b>Select a scan first.</b></section>; const r=scan.result||{},ind=r.indicators||{},pe=r.pe_analysis||{}; return <><div className="page-head"><div><p className="eyebrow">ANALYSIS REPORT #{scan.id}</p><h1>{scan.original_filename}</h1><p>Analyzed by {scan.analyst.full_name} · {new Date(scan.created_at).toLocaleString()}</p></div><RiskBadge score={scan.risk_score} label={scan.classification}/></div><section className="metric-grid report-metrics"><div className="metric-card wide-metric"><span>SHA-256</span><strong className="mono">{scan.sha256}</strong></div><div className="metric-card"><span>MD5</span><strong className="mono">{scan.md5}</strong></div><div className="metric-card"><span>File type</span><strong>{scan.file_type}</strong></div></section><div className="dashboard-grid"><ReportBox title="Risk reasoning">{r.risk?.reasons?.length?<ul>{r.risk.reasons.map(x=><li key={x}>{x}</li>)}</ul>:<p className="muted">No suspicious indicators recorded.</p>}<small>Method: {r.risk?.method}</small></ReportBox><ReportBox title="YARA matches">{r.yara_matches?.length?r.yara_matches.map(m=><div className="result-row" key={m.rule}><b>{m.rule}</b><span>{m.meta?.severity||'medium'} · {m.meta?.category||'static'}</span></div>):<p className="muted">No local YARA rule matched.</p>}</ReportBox><ReportBox title="Indicators"><p><b>URLs:</b> {ind.urls?.length||0}</p><p><b>IPv4:</b> {ind.ipv4?.length||0}</p><p><b>Suspicious strings:</b> {r.suspicious_strings?.length||0}</p></ReportBox><ReportBox title="Signature match">{r.signature_match?.matched?<div className="result-row"><b>{r.signature_match.name}</b><span>{r.signature_match.description}</span></div>:<p className="muted">No local signature match.</p>}</ReportBox></div>{pe.is_pe&&<section className="panel"><h3>PE analysis</h3><p>Machine: <span className="mono">{pe.machine}</span> · Subsystem: <span className="mono">{pe.subsystem}</span></p></section>}</> }
function ReportBox({title,children}){return <section className="panel"><p className="eyebrow">STATIC ANALYSIS</p><h3>{title}</h3>{children}</section>}

function Users() { const [users,setUsers]=useState([]),[stats,setStats]=useState(null),[form,setForm]=useState({full_name:'',email:'',password:'',role:'researcher'}),[error,setError]=useState(''),[message,setMessage]=useState(''); async function load(){try{setUsers(await api('/api/users'));setStats(await api('/api/users/stats/summary'))}catch(e){setError(e.message)}} useEffect(()=>{load()},[]); async function create(e){e.preventDefault();setError('');setMessage('');try{await api('/api/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(form)});setForm({full_name:'',email:'',password:'',role:'researcher'});setMessage('User created successfully.');load()}catch(e){setError(e.message)}} async function role(id,role){setError('');try{await api(`/api/users/${id}/role`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({role})});load()}catch(e){setError(e.message)}} async function toggle(u){setError('');try{await api(`/api/users/${u.id}/status`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({active:!u.active})});load()}catch(e){setError(e.message)}} return <><div className="page-head"><div><p className="eyebrow">ADMINISTRATION</p><h1>User management</h1><p>Control identities, roles and account status.</p></div><span className="role-chip purple">ADMIN ONLY</span></div>{stats&&<div className="metric-grid"><Metric n={stats.total_users} l="Total users"/><Metric n={stats.active_users} l="Active users"/><Metric n={stats.total_scans} l="Total scans"/><Metric n={stats.potential_malware_scans} l="Potential malware"/></div>}<section className="panel"><div className="panel-head"><div><p className="eyebrow">IDENTITIES</p><h3>Platform users</h3></div><span className="live-dot">● RBAC enforced</span></div>{error&&<div className="error">{error}</div>}<div className="table-wrap"><table><thead><tr><th>User</th><th>Role</th><th>Status</th><th>Created</th><th>Action</th></tr></thead><tbody>{users.map(u=><tr key={u.id}><td><div className="user-cell"><div className="avatar small">{u.full_name.slice(0,1).toUpperCase()}</div><div><b>{u.full_name}</b><small>{u.email}</small></div></div></td><td><select value={u.role} onChange={e=>role(u.id,e.target.value)}><option value="administrator">Administrator</option><option value="security_analyst">Security Analyst</option><option value="soc_member">SOC Team Member</option><option value="researcher">Researcher</option></select></td><td><span className={`status ${u.active?'on':'off'}`}>● {u.active?'Active':'Inactive'}</span></td><td>{new Date(u.created_at).toLocaleDateString()}</td><td><button onClick={()=>toggle(u)}>{u.active?'Deactivate':'Activate'}</button></td></tr>)}</tbody></table></div></section><section className="panel"><div className="panel-head"><div><p className="eyebrow">CREATE IDENTITY</p><h3>Add a platform user</h3></div></div>{message&&<div className="success">{message}</div>}<form className="form-grid" onSubmit={create}><label>Full name<input required value={form.full_name} onChange={e=>setForm({...form,full_name:e.target.value})}/></label><label>Email<input required type="email" value={form.email} onChange={e=>setForm({...form,email:e.target.value})}/></label><label>Password<input required minLength="8" type="password" value={form.password} onChange={e=>setForm({...form,password:e.target.value})}/></label><label>Role<select value={form.role} onChange={e=>setForm({...form,role:e.target.value})}><option value="security_analyst">Security Analyst</option><option value="soc_member">SOC Team Member</option><option value="researcher">Researcher</option><option value="administrator">Administrator</option></select></label><button className="primary">Create user →</button></form></section></> }

function Profile({ user, onUpdate }) { const [name,setName]=useState(user.full_name),[email,setEmail]=useState(user.email),[current,setCurrent]=useState(''),[next,setNext]=useState(''),[msg,setMsg]=useState(''),[error,setError]=useState(''); async function save(e){e.preventDefault();setMsg('');setError('');try{const u=await api('/api/auth/profile',{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({full_name:name,email})});onUpdate(u);setMsg('Profile updated successfully.')}catch(e){setError(e.message)}} async function pwd(e){e.preventDefault();setMsg('');setError('');try{await api('/api/auth/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:current,new_password:next})});setCurrent('');setNext('');setMsg('Password changed successfully.')}catch(e){setError(e.message)}} return <><div className="page-head"><div><p className="eyebrow">ACCOUNT</p><h1>Your profile</h1><p>Manage your identity and authentication settings.</p></div></div><section className="panel profile-panel"><div className="profile-hero"><div className="avatar large">{user.full_name.slice(0,1).toUpperCase()}</div><div><h2>{user.full_name}</h2><p>{ROLE_LABELS[user.role]} · {user.email}</p></div></div>{msg&&<div className="success">{msg}</div>}{error&&<div className="error">{error}</div>}<form className="form-grid" onSubmit={save}><label>Full name<input value={name} onChange={e=>setName(e.target.value)}/></label><label>Email<input type="email" value={email} onChange={e=>setEmail(e.target.value)}/></label><label>Role<input disabled value={ROLE_LABELS[user.role]}/></label><button className="primary">Save profile →</button></form></section><section className="panel"><p className="eyebrow">AUTHENTICATION</p><h3>Change password</h3><form className="form-grid"><label>Current password<input type="password" required value={current} onChange={e=>setCurrent(e.target.value)}/></label><label>New password<input type="password" minLength="8" required value={next} onChange={e=>setNext(e.target.value)}/></label><button className="primary" onClick={pwd}>Change password →</button></form></section></> }

function YaraRules() { const [rules,setRules]=useState([]),[error,setError]=useState(''); useEffect(()=>{api('/api/users/yara/rules').then(setRules).catch(e=>setError(e.message))},[]); return <><div className="page-head"><div><p className="eyebrow">STATIC DETECTION</p><h1>YARA rule library</h1><p>Local educational rules for safe static matching. Samples are never executed.</p></div><span className="pill">{rules.length} RULES LOADED</span></div><section className="rule-grid">{error&&<div className="error">{error}</div>}{rules.map(r=><article className="rule-card" key={r.name}><div className="rule-top"><span className="rule-icon">◈</span><span className="badge warning">{r.severity}</span></div><h3>{r.name}</h3><p>{r.description}</p><div className="rule-meta"><span>{r.category}</span><span>{r.file}</span></div></article>)}</section></> }

function App() { const [user,setUser]=useState(null),[active,setActive]=useState('overview'),[scan,setScan]=useState(null); useEffect(()=>{if(localStorage.getItem('threatlens_token'))api('/api/auth/me').then(setUser).catch(()=>localStorage.removeItem('threatlens_token'))},[]); if(!user)return <Auth onLogin={u=>{setUser(u);setActive('overview')}}/>; async function openScan(id){try{setScan(await api(`/api/scans/${id}`));setActive('report')}catch(e){alert(e.message)}} function logout(){localStorage.removeItem('threatlens_token');setUser(null)} const page=active==='overview'?<Overview user={user} setActive={setActive}/>:active==='analysis'&&user.role!=='soc_member'?<Analysis onScan={s=>{setScan(s);setActive('report')}}/>:active==='history'?<History onOpen={openScan}/>:active==='report'?<Report scan={scan}/>:active==='users'&&user.role==='administrator'?<Users/>:active==='profile'?<Profile user={user} onUpdate={setUser}/>:<YaraRules/>; return <Layout user={user} onLogout={logout} active={active} setActive={setActive}>{page}</Layout>; }
export default App;
