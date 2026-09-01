from __future__ import annotations
import hashlib, json, mimetypes, os, re, uuid
from pathlib import Path
from typing import Any
import pefile
import yara

BASE_DIR = Path(__file__).resolve().parents[2]
YARA_DIR = BASE_DIR / "yara_rules"
SIGNATURE_FILE = YARA_DIR / "signatures.json"

SUSPICIOUS_TERMS = {"powershell":15,"cmd.exe":10,"wscript":12,"cscript":12,"rundll32":10,"regsvr32":10,"mshta":12,"downloadstring":18,"invoke-expression":18,"frombase64string":15,"schtasks":8,"vssadmin":8,"bitsadmin":8,"certutil":8,"wmic":8,"net user":5}
URL_RE = re.compile(rb"https?://[^\s\x00\"'<>]{4,250}", re.I)
IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")

def _safe_text(value: bytes, max_len=500): return value.decode("utf-8", errors="replace")[:max_len]

def _extract_strings(data: bytes, limit=500):
    found=[]
    for match in ASCII_RE.findall(data):
        found.append(_safe_text(match))
        if len(found)>=limit: break
    if len(found)<limit:
        for match in UTF16_RE.findall(data):
            found.append(_safe_text(match.replace(b"\x00",b"")))
            if len(found)>=limit: break
    return list(dict.fromkeys(found))

def _valid_ip(ip): return all(0 <= int(p) <= 255 for p in ip.split('.'))

def _extract_indicators(data):
    urls=list(dict.fromkeys(_safe_text(x) for x in URL_RE.findall(data)))[:100]
    ips=[]
    for x in IP_RE.findall(data):
        item=_safe_text(x)
        if _valid_ip(item) and item not in ips: ips.append(item)
    return {"urls":urls,"ipv4":ips[:100]}

def _file_type(path, data):
    if data.startswith(b'MZ'):
        return "Windows PE executable", "application/vnd.microsoft.portable-executable"
    mime=mimetypes.guess_type(path)[0] or "application/octet-stream"
    desc={"text/plain":"Plain text","application/pdf":"PDF document","application/zip":"ZIP archive","image/png":"PNG image","image/jpeg":"JPEG image"}.get(mime,mime)
    return desc,mime

def _pe_analysis(data):
    result={"is_pe":False,"machine":None,"subsystem":None,"timestamp":None,"sections":[],"imports":[]}
    try: pe=pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError: return result
    result.update(is_pe=True,machine=hex(pe.FILE_HEADER.Machine),timestamp=pe.FILE_HEADER.TimeDateStamp)
    if hasattr(pe,'OPTIONAL_HEADER'): result['subsystem']=hex(pe.OPTIONAL_HEADER.Subsystem)
    for section in pe.sections:
        name=section.Name.rstrip(b'\x00').decode('ascii',errors='replace')
        result['sections'].append({"name":name,"virtual_size":section.Misc_VirtualSize,"raw_size":section.SizeOfRawData,"entropy":round(section.get_entropy(),3),"characteristics":hex(section.Characteristics)})
    if hasattr(pe,'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll=entry.dll.decode(errors='replace')
            for imp in entry.imports[:100]: result['imports'].append({"dll":dll,"name":imp.name.decode(errors='replace') if imp.name else f"ordinal_{imp.ordinal}"})
    return result

def _load_yara():
    paths=sorted(YARA_DIR.glob('*.yar'))
    return yara.compile(filepaths={f"rule_{i}":str(p) for i,p in enumerate(paths)}) if paths else None

def list_yara_rules():
    rules=[]
    for p in sorted(YARA_DIR.glob('*.yar')):
        text=p.read_text(encoding='utf-8',errors='replace')
        # Metadata is parsed conservatively for the UI; YARA itself remains the source of truth for matching.
        names=re.findall(r'\brule\s+([A-Za-z0-9_]+)',text)
        for name in names:
            block=text[text.find('rule '+name):]
            def meta(k,d):
                m=re.search(rf'{k}\s*=\s*"([^"]*)"',block)
                return m.group(1) if m else d
            rules.append({"name":name,"description":meta('description','Educational static-analysis rule'),"severity":meta('severity','medium'),"category":meta('category','static'),"file":p.name})
    return rules

def _signature_match(sha256):
    if not SIGNATURE_FILE.exists(): return {"matched":False,"name":None,"description":None}
    data=json.loads(SIGNATURE_FILE.read_text(encoding='utf-8'))
    hit=data.get(sha256.lower())
    return {"matched":False,"name":None,"description":None} if not hit else {"matched":True,**hit}

def analyze_file(path):
    data=Path(path).read_bytes(); size=len(data)
    md5=hashlib.md5(data).hexdigest(); sha256=hashlib.sha256(data).hexdigest()
    description,mime=_file_type(path,data)
    strings=_extract_strings(data); indicators=_extract_indicators(data); pe=_pe_analysis(data); signature=_signature_match(sha256)
    lower=[s.lower() for s in strings]; suspicious=[]
    for term,points in SUSPICIOUS_TERMS.items():
        count=sum(term in s for s in lower)
        if count: suspicious.append({"term":term,"occurrences":count,"points":points})
    yara_matches=[]; rules=_load_yara()
    if rules:
        for match in rules.match(path): yara_matches.append({"rule":match.rule,"namespace":match.namespace,"tags":list(match.tags),"meta":dict(match.meta)})
    score=0; reasons=[]
    if pe['is_pe']: score+=10; reasons.append('Windows PE executable detected')
    if indicators['urls']: score+=min(20,5+len(indicators['urls'])*2); reasons.append(f"{len(indicators['urls'])} embedded URL indicator(s) found")
    if indicators['ipv4']: score+=min(15,len(indicators['ipv4'])*2); reasons.append(f"{len(indicators['ipv4'])} IPv4 indicator(s) found")
    for hit in suspicious: score+=min(hit['points'],20); reasons.append(f"Suspicious string: {hit['term']}")
    if yara_matches: score+=min(40,20+len(yara_matches)*10); reasons.append(f"{len(yara_matches)} YARA rule(s) matched")
    if signature['matched']: score=max(score,95); reasons.append(f"Known signature match: {signature['name']}")
    score=min(score,100)
    classification='Potential Malware' if signature['matched'] or score>=75 else ('Suspicious' if score>=40 else 'No Strong Indicators')
    return {"hashes":{"md5":md5,"sha256":sha256},"metadata":{"size_bytes":size,"file_name":os.path.basename(path),"mime_type":mime,"file_description":description},"pe_analysis":pe,"strings":strings,"indicators":indicators,"signature_match":signature,"suspicious_strings":suspicious,"yara_matches":yara_matches,"risk":{"score":score,"classification":classification,"reasons":reasons,"method":"Milestone 1 heuristic/static rules; not an ML prediction"}}

def store_uploaded_bytes(upload_dir, original_name, data):
    Path(upload_dir).mkdir(parents=True,exist_ok=True)
    suffix=Path(original_name).suffix[:10]
    stored=f"{uuid.uuid4().hex}{suffix}"
    (Path(upload_dir)/stored).write_bytes(data)
    return stored
