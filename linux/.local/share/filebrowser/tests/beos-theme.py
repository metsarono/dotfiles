from pathlib import Path
import copy,json,subprocess,tempfile,yaml,base64,re,struct,zlib
import os
repo=Path(os.environ.get('DOTCORTEX_REPO', Path.cwd()))
helper=repo/'linux/.local/bin/filebrowser-theme-apply';assets=repo/'linux/.local/share/filebrowser/themes/beos-r5'
checks=0
with tempfile.TemporaryDirectory(prefix='fb-beos-transitions-') as tmp:
 config=Path(tmp)/'config.yaml'
 seed={'server':{'database':'fixture-only.db','sources':[{'name':'fixture','path':'fixture-only'}]},'frontend':{'name':'Keep Me','styling':{'customCSS':'old.css','darkBackground':'#111111'}},'auth':{'tokenExpirationHours':720},'integrations':{'office':{'url':'fixture-url'}},'userDefaults':{'fileViewer':{'preferEditorForMarkdown':True}}}
 def run(theme,apply=True,ok=True):
  global checks
  args=['python3',str(helper),theme,'--config',str(config),'--assets',str(assets)]+(['--apply'] if apply else [])
  r=subprocess.run(args,capture_output=True,text=True)
  assert (r.returncode==0)==ok,(r.stdout,r.stderr)
  checks+=1
  return r
 config.write_text(yaml.safe_dump(seed));original=config.read_bytes()
 run('beos-r5',False);assert config.read_bytes()==original;assert len(list(Path(tmp).iterdir()))==1
 run('beos-r5');enabled=yaml.safe_load(config.read_text());receipt=(Path(tmp)/'.beos-r5-theme.json').read_bytes()
 d=copy.deepcopy(enabled);d['frontend']['styling']['customCSS']='old.css';assert d==seed
 css=Path(enabled['frontend']['styling']['customCSS']).read_text();assert len(css.encode())<=128*1024
 fonts=(assets/'fonts.css').read_text()
 for t,w in zip(re.findall(r'data:font/ttf;base64,([A-Za-z0-9+/=]+)',fonts),re.findall(r'data:font/woff;base64,([A-Za-z0-9+/=]+)',css)):
  raw=base64.b64decode(t);packed=base64.b64decode(w);n=struct.unpack_from('>H',packed,12)[0]
  for i in range(n):
   tag,o,c,l,sum1=struct.unpack_from('>4sIIII',packed,44+20*i)
   body=packed[o:o+c];body=zlib.decompress(body) if c<l else body
   tag2,sum2,start,l2=struct.unpack_from('>4sIII',raw,12+16*i)
   assert(tag,l,sum1,body)==(tag2,l2,sum2,raw[start:start+l2])
 checks+=1
 before=config.read_bytes();run('beos-r5');assert config.read_bytes()==before;assert (Path(tmp)/'.beos-r5-theme.json').read_bytes()==receipt
 d=copy.deepcopy(enabled);d['auth']['tokenExpirationHours']=1000;config.write_text(yaml.safe_dump(d))
 run('off',False);assert yaml.safe_load(config.read_text())==d
 run('off');seed['auth']['tokenExpirationHours']=1000;assert yaml.safe_load(config.read_text())==seed
 run('off');run('beos-r5');d=yaml.safe_load(config.read_text());d['frontend']['styling']['customCSS']='someone-elses.css';config.write_text(yaml.safe_dump(d));before=config.read_bytes()
 run('off',ok=False);run('beos-r5',ok=False);assert config.read_bytes()==before
 # Missing frontend must return to absent, rather than adding empty maps.
 (Path(tmp)/'.beos-r5-theme.json').unlink();config.write_text('server: {}\n');run('beos-r5');run('off');assert yaml.safe_load(config.read_text())=={'server':{}}
 config.write_text('frontend: {}\nfrontend: {}\n');run('beos-r5',ok=False)
 config.unlink();config.symlink_to(Path(tmp)/'other.yaml');(Path(tmp)/'other.yaml').write_text('server: {}\n');run('beos-r5',ok=False)
print(f'PASS: {checks} transitions/guards, field-only rollback, unrelated settings preserved, cap and font table identity')
