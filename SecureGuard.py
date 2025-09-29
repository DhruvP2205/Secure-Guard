#!/usr/bin/env python3
import os,re,json,math,sys,subprocess,tempfile,shutil
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor,as_completed
from collections import Counter
from datetime import datetime,timedelta

def install_package(package):
    print(f"Installing {package}...")
    subprocess.check_call([sys.executable,"-m","pip","install",package],stdout=subprocess.DEVNULL)

packages=[('click','click'),('gitpython','git'),('rich','rich'),('orjson','orjson')]
for pip_name,import_name in packages:
    try:__import__(import_name)
    except ImportError:install_package(pip_name)

import click,git,orjson
from rich.console import Console
from rich.table import Table
from rich.progress import Progress,SpinnerColumn,TextColumn,BarColumn
from rich.panel import Panel

console=Console()

SECRET_PATTERNS={
    'Google API Key':re.compile(r'AIza[0-9A-Za-z-_]{35}'),'Firebase':re.compile(r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}'),
    'AWS Access Key':re.compile(r'A[SK]IA[0-9A-Z]{16}'),'Amazon MWS':re.compile(r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
    'Facebook Token':re.compile(r'EAACEdEose0cBA[0-9A-Za-z]+'),'Basic Auth':re.compile(r'basic\s+[a-zA-Z0-9=:_\+\/-]{20,100}',re.IGNORECASE),
    'Bearer Token':re.compile(r'bearer\s+[a-zA-Z0-9_\-\.=:_\+\/]{20,100}',re.IGNORECASE),
    'API Key Assignment':re.compile(r'[\'"]?api[_-]?key[\'"]?\s*[:=]\s*[\'"][A-Za-z0-9_-]{16,}[\'"]',re.IGNORECASE),
    'Mailgun API':re.compile(r'key-[0-9a-zA-Z]{32}'),'Twilio API':re.compile(r'SK[0-9a-fA-F]{32}'),'Twilio SID':re.compile(r'AC[a-zA-Z0-9_\-]{32}'),
    'Stripe Live':re.compile(r'sk_live_[0-9a-zA-Z]{24}'),'Stripe Test':re.compile(r'sk_test_[0-9a-zA-Z]{24}'),
    'GitHub Token':re.compile(r'ghp_[A-Za-z0-9]{36}|[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com'),
    'RSA Private':re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),'DSA Private':re.compile(r'-----BEGIN DSA PRIVATE KEY-----'),
    'EC Private':re.compile(r'-----BEGIN EC PRIVATE KEY-----'),'SSH Private':re.compile(r'-----BEGIN [A-Z]+ PRIVATE KEY-----'),
    'JWT Token':re.compile(r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+'), 'Slack Token':re.compile(r'"api_token":"(xox[a-zA-Z]-[a-zA-Z0-9-]+)"'),
    'Heroku API':re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'),
    'Password Assignment':re.compile(r'[\'"]?(?:password|passwd|pass|pwd|secret)[\'"]?\s*[:=]\s*[\'"][^\'"\s]{6,}[\'"]',re.IGNORECASE),
    'Database URI':re.compile(r'(mysql|postgres|postgresql|mongodb|redis)://[^:\s]+:[^@\s]+@[^/\s]+/[^\s]+'),
    'SMTP Password':re.compile(r'[\'"]?smtp[_-]?(?:password|pass)[\'"]?\s*[:=]\s*[\'"][^\'"\s]{6,}[\'"]',re.IGNORECASE),
    'DB Credentials':re.compile(r'[\'"]?db[_-]?(?:password|pass|user)[\'"]?\s*[:=]\s*[\'"][^\'"\s]{4,}[\'"]',re.IGNORECASE),
    'JWT Secret':re.compile(r'[\'"]?jwt[_-]?secret[\'"]?\s*[:=]\s*[\'"][^\'"\s]{12,}[\'"]',re.IGNORECASE), 'Discord Token':re.compile(r'[MN][A-Za-z\d]{23}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27}'),
    'PHP Variable Assignment': re.compile(r'\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*[\'"][^\'"]{6,}[\'"]'),
    'Java String Assignment': re.compile(r'(dbPassword|apiToken)\s*=\s*[\'"][^\'"]{8,}[\'"]'),
    'Environment Variable': re.compile(r'^[A-Z_]+=.{6,}$', re.MULTILINE),
    'JSON String Value': re.compile(r'[\'"](?:password|secret|key)[\'"]:\s*[\'"][^\'"]{6,}[\'"]'),
    'Config File Assignment': re.compile(r'[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*[^\s\'"]{8,}'),
    'GitHub Personal Token': re.compile(r'ghp_[A-Za-z0-9]{36}'),
    'Python Assignment': re.compile(r'[A-Z_]+\s*=\s*[\'"](?:sk_test_|postgres://)[^\'"]+[\'"]'),
    'PHP Variable': re.compile(r'\$(?:db_pass|smtp_password)\s*=\s*[\'"][^\'"]+[\'"]'),
    'Java String': re.compile(r'(?:dbPassword|apiToken)\s*=\s*[\'"][^\'"]+[\'"]'),
    'JSON Value': re.compile(r'[\'"](?:smtp_password)[\'"]:\s*[\'"][^\'"]+[\'"]'),
    'Stripe Key': re.compile(r'sk_test_[0-9a-zA-Z]{24,}'),
    'Python String Assignment': re.compile(r'[A-Z_]+\s*=\s*[\'"][^\'"]{10,}[\'"]'),
    'PHP Variable': re.compile(r'\$[a-zA-Z_]+\s*=\s*[\'"][^\'"]{6,}[\'"]'),
    'Java Field Assignment': re.compile(r'String\s+\w+\s*=\s*[\'"][^\'"]{8,}[\'"]'), 'JSON Password Field': re.compile(r'[\'"][\w_]*password[\'"]:\s*[\'"][^\'"]{6,}[\'"]'), 'PHP Password': re.compile(r'\$(?:db_pass|smtp_password)\s*=\s*[\'"][^\'"\s]{6,}[\'"]'), 'Java String Field': re.compile(r'(?:dbPassword|apiToken)\s*=\s*[\'"][^\'"\s]{8,}[\'"]'), 'JSON Password': re.compile(r'[\'"]smtp_password[\'"]:\s*[\'"][^\'"\s]{6,}[\'"]'), 'Python Variable': re.compile(r'[A-Z_]+\s*=\s*[\'"](?:sk_test_|postgres://)[^\'"\s]{10,}[\'"]'),
}

SENSITIVE_FILES={'.env','.env.local','.env.production','.gitignore','.git/config','.npmrc','id_rsa','id_dsa','id_ecdsa','config.json','credentials','secrets.yml','secrets.yaml','.aws/credentials','.ssh/id_rsa','docker-compose.yml','Dockerfile','.dockerignore','wp-config.php','database.yml','keystore.jks'}
SKIP_DIRS={'node_modules','vendor','composer','dist','build','__pycache__','.git','venv','env','.venv'}
SKIP_FILES={'package-lock.json','yarn.lock','composer.lock','Pipfile.lock','poetry.lock','Gemfile.lock', 'composer.phar'}
SKIP_EXTENSIONS={'.jpg','.jpeg','.png','.gif','.bmp','.ico','.svg','.pdf','.zip','.tar','.gz','.mp4','.avi','.mov','.rar','.7z'}
DUMMY_VALUES={'password=12345','changeme','example.com','localhost','127.0.0.1','test','demo','sample','password','Password','placeholder','className','htmlFor','type','string','required','minlength','minLength', 'integrity'}
SEVERITY_MAP={'AWS Access Key':'CRITICAL','RSA Private':'CRITICAL','DSA Private':'CRITICAL','EC Private':'CRITICAL','SSH Private':'CRITICAL','GitHub Token':'HIGH','Stripe Live':'HIGH','Stripe Test':'HIGH','JWT Token':'HIGH','Firebase':'HIGH','Google API Key':'HIGH','Facebook Token':'HIGH','Twilio API':'HIGH','Twilio SID':'HIGH','Mailgun API':'HIGH','Password Assignment':'MEDIUM','API Key Assignment':'MEDIUM','Basic Auth':'MEDIUM','Bearer Token':'MEDIUM','DB Credentials':'MEDIUM','SMTP Password':'MEDIUM','JWT Secret':'MEDIUM','High Entropy':'LOW','Sensitive File':'LOW','Heroku API':'MEDIUM','Database URI':'HIGH'}

class SecretScanner:
    def __init__(self,repo_root=None):
        self.findings,self.repo_root=[],repo_root
        self.stats={'files_scanned':0,'total_files':0,'critical':0,'high':0,'medium':0,'low':0}
    
    def calculate_entropy(self,text):
        if len(text)<8:return 0
        frequency=Counter(text)
        return -sum((count/len(text))*math.log2(count/len(text)) for count in frequency.values())
    
    def is_binary_file(self,file_path):
        try:
            with open(file_path,'rb') as f:return b'\x00' in f.read(1024)
        except:return True
    
    def get_relative_path(self,file_path):
        if self.repo_root:
            try:return str(Path(file_path).relative_to(self.repo_root))
            except:return str(file_path)
        return str(file_path)
    
    def contains_dummy(self,text):
        text_lower=text.lower().strip()
        return any(dummy in text_lower for dummy in DUMMY_VALUES) or len(text.strip())<8
    
    def is_likely_code_structure(self,line,match):
        stripped_line=line.strip().lower()
        if any(pattern in stripped_line for pattern in ['type:','minlength:','required:','string','schema','validation','interface ','class ','function ','const [','let [','useState','setpassword', 'integrity=']):return True
        if re.search(r'^\s*[\'"][a-z_]+[\'"]:\s*\{',line,re.IGNORECASE):return True
        if '"type"' in stripped_line and '"string"' in stripped_line:return True
        return False
    
    def scan_file_content(self,file_path,content):
        findings,relative_path=[],self.get_relative_path(file_path)
        for line_num,line in enumerate(content.split('\n'),1):
            if line.strip().startswith(('#','//','/*')) or self.contains_dummy(line):continue
            
            for rule_name,pattern in SECRET_PATTERNS.items():
                matches=pattern.findall(line)
                for match in matches:
                    match_str=match if isinstance(match,str) else ' '.join(match)
                    if not self.contains_dummy(match_str) and not self.is_likely_code_structure(line,match_str) and len(match_str.strip())>8:
                        severity=SEVERITY_MAP.get(rule_name,'MEDIUM')
                        findings.append({'file':relative_path,'line':line_num,'match':match_str[:100],'rule':rule_name,'severity':severity,'full_line':line.strip()[:200]})
                        self.stats[severity.lower()]+=1
            
            words=re.findall(r'\b[A-Za-z0-9+/=]{32,}\b',line)
            for word in words:
                if self.calculate_entropy(word)>4.8 and not self.contains_dummy(word) and not self.is_likely_code_structure(line,word):
                    findings.append({'file':relative_path,'line':line_num,'match':word[:100],'rule':'High Entropy','severity':'LOW','full_line':line.strip()[:200]})
                    self.stats['low']+=1
        return findings
    
    def scan_file(self,file_path):
        try:
            file_path=Path(file_path)
            if file_path.stat().st_size>10*1024*1024 or file_path.suffix.lower() in SKIP_EXTENSIONS:return []
            if file_path.name in SKIP_FILES or self.is_binary_file(file_path):return []
            findings,relative_path=[],self.get_relative_path(file_path)
            if file_path.name in SENSITIVE_FILES or any(sf in str(file_path) for sf in SENSITIVE_FILES):
                findings.append({'file':relative_path,'line':0,'match':f'Sensitive file: {file_path.name}','rule':'Sensitive File','severity':'LOW','full_line':''})
                self.stats['low']+=1
            
            with open(file_path,'r',encoding='utf-8',errors='ignore') as f:content=f.read()
            findings.extend(self.scan_file_content(file_path,content))
            self.stats['files_scanned']+=1
            return findings
        except:return []
    
    def get_files_to_scan(self,root_path):
        root_path=Path(root_path)
        if root_path.is_file():return [root_path]
        return [item for item in root_path.rglob('*') if item.is_file() and not any(skip_dir in item.parts for skip_dir in SKIP_DIRS)]
    
    def scan_recent_commits(self,repo_path,days=7):
        try:
            repo=git.Repo(repo_path)
            since_date=datetime.now()-timedelta(days=days)
            commits=list(repo.iter_commits(since=since_date))
            recent_files=set()
            for commit in commits:
                for item in commit.stats.files:
                    file_path=repo_path/item
                    if file_path.exists():recent_files.add(file_path)
            return list(recent_files)
        except:return []
    
    def scan_directory(self,path,max_workers=4,recent_only=False):
        files=self.scan_recent_commits(path) if recent_only else self.get_files_to_scan(path)
        self.stats['total_files']=len(files)
        findings=[]
        with Progress(SpinnerColumn(),TextColumn("[progress.description]{task.description}"),BarColumn(),TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),console=console) as progress:
            task=progress.add_task(f"🔍 Scanning {len(files)} files...",total=len(files))
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_file={executor.submit(self.scan_file,file):file for file in files}
                for future in as_completed(future_to_file):
                    findings.extend(future.result())
                    progress.advance(task)
        
        self.findings=findings
        return findings

def safe_rmtree(path):
    def handle_remove_readonly(func,path,exc):
        os.chmod(path,0o777)
        func(path)
    try:shutil.rmtree(path,onerror=handle_remove_readonly)
    except:pass

def clone_repository(url,branch='main'):
    try:
        repo_name=url.split('/')[-1].replace('.git','')
        repo_path=Path.cwd()/f"scanned_{repo_name}"
        if repo_path.exists():safe_rmtree(repo_path)
        console.print(f"[blue]📥 Cloning branch '{branch}' from: {url}[/blue]")
        git.Repo.clone_from(url,repo_path,branch=branch,depth=1)
        return repo_path
    except Exception as e:
        try:
            git.Repo.clone_from(url,repo_path,depth=1)
            return repo_path
        except:raise click.ClickException(f"Failed to clone repository: {str(e)}")

def print_findings(findings,stats):
    if not findings:
        console.print(Panel("[green]🎉 No sensitive data found![/green]",title="Scan Results"))
        return
    
    table=Table(title="🔍 Security Findings")
    table.add_column("Severity",style="bold",width=8)
    table.add_column("File",style="cyan",no_wrap=True)
    table.add_column("Line",style="magenta",width=6)
    table.add_column("Rule",style="red")
    table.add_column("Match Preview",style="yellow")
    
    severity_colors={'CRITICAL':'red','HIGH':'orange1','MEDIUM':'yellow','LOW':'blue'}
    
    for finding in sorted(findings,key=lambda x:['CRITICAL','HIGH','MEDIUM','LOW'].index(x['severity'])):
        color=severity_colors.get(finding['severity'],'white')
        line_str=str(finding['line']) if finding['line']>0 else "N/A"
        match_preview=finding['match'][:40]+"..." if len(finding['match'])>40 else finding['match']
        table.add_row(f"[{color}]{finding['severity']}[/{color}]",finding['file'],line_str,finding['rule'],match_preview)
    
    console.print(table)
    stats_panel=f"""[red]Critical: {stats['critical']}[/red] | [orange1]High: {stats['high']}[/orange1] | [yellow]Medium: {stats['medium']}[/yellow] | [blue]Low: {stats['low']}[/blue]
Files Scanned: {stats['files_scanned']}/{stats['total_files']} | Total Issues: {len(findings)}"""
    console.print(Panel(stats_panel,title="📊 Scan Statistics"))

@click.command()
@click.argument('target')
@click.option('--branch','-b',default='main',help='Git branch to clone (default: main)')
@click.option('--json','json_output',help='Save findings to JSON file')
@click.option('--workers','-w',default=4,help='Number of worker threads (default: 4)')
@click.option('--recent','-r',is_flag=True,help='Scan only recently modified files (last 7 days)')
@click.option('--cleanup/--no-cleanup',default=True,help='Remove cloned repository after scan')
def main(target,branch,json_output,workers,recent,cleanup):
    """
    🔍 SecureGuard: Advanced Secret Scanner - Find credentials, API keys, and sensitive data
    
    TARGET can be a local directory/file or remote Git repository URL
    
    Examples:\n
        SecureGuard /path/to/project\n
        SecureGuard https://github.com/user/repo.git -b develop\n
        SecureGuard ./src --json report.json --recent
    """
    scanner=SecretScanner()
    cloned_repo=None
    try:
        if target.startswith(('http://','https://','git@')):
            scan_path=clone_repository(target,branch)
            cloned_repo=scan_path
            scanner.repo_root=scan_path
        else:
            scan_path=Path(target)
            if not scan_path.exists():raise click.ClickException(f"Path does not exist: {target}")
        
        console.print(f"[blue]🔍 Starting {'recent files ' if recent else ''}scan of: {scan_path}[/blue]")
        findings=scanner.scan_directory(scan_path,max_workers=workers,recent_only=recent)
        
        if json_output:
            report={'scan_summary':{'total_findings':len(findings),'timestamp':str(datetime.now()),'target':str(scan_path),'stats':scanner.stats},'findings':findings}
            with open(json_output,'wb') as f:f.write(orjson.dumps(report,option=orjson.OPT_INDENT_2))
            console.print(f"[green]✅ Report saved: {json_output}[/green]")
        
        print_findings(findings,scanner.stats)
        
        if cloned_repo:
            console.print(f"[cyan]📁 Repository cloned to: {cloned_repo}[/cyan]")
            if cleanup:
                console.print("[yellow]🧹 Cleaning up cloned repository...[/yellow]")
                safe_rmtree(cloned_repo)
            
    except KeyboardInterrupt:console.print("\n[yellow]⚠️ Scan interrupted by user[/yellow]")
    except Exception as e:console.print(f"[red]❌ Error: {str(e)}[/red]")
    finally:
        if cloned_repo and cleanup and cloned_repo.exists():safe_rmtree(cloned_repo)

if __name__=='__main__':main()
