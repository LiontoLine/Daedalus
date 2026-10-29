"""Fixed small engineering workloads. Oracles never enter an arm's repository."""

# Embedded fixture sources intentionally retain their exact whitespace and long lines.
# ruff: noqa: E501

from textwrap import dedent

from daedalus.application.benchmark_cases import BenchmarkCase


def text(value):
    return dedent(value).strip() + "\n"


def node(script):
    return "\n    import subprocess\n    subprocess.run(['node','-e'," + repr(script) + "],check=True)\n"


def case(key, category, contract, files, answers, public, hidden):
    return BenchmarkCase(
        key=key, category=category,
        objective=f"{category}. Implement docs/contract.md without changing public APIs, tests, "
        "read-only helpers or dependencies. Preserve unrelated behavior. Use standard libraries only.",
        initial="", public=text(public), heldout=text(hidden), answer="",
        files=(*((name, text(body)) for name, body in files.items()),
               ("docs/contract.md", text(contract))),
        targets=tuple(answers), references=("docs/contract.md",),
        answer_files=tuple((name, text(body)) for name, body in answers.items()),
    )


PAGINATION = case(
    "api_pagination", "API pagination + browser state",
    """
    Deliver a stable task-list API and its existing browser helpers.
    api.list_response(rows, query) returns (status, JSON-compatible body).
    Valid status filters: open/done, or empty for all; unknown filters -> 400.
    limit is 1..50 (default 20); invalid/bool/negative values -> 400.
    Sort by contracts.sort_key, then return at most limit items and next_cursor (or None).
    Equal timestamps must not lose items or cause duplicates. Do not mutate rows or query.
    cursor.pack(after,status)/unpack(token) round-trip an after key and filter binding.
    Invalid, malformed or differently filtered cursors -> 400. Cursor contents are data,
    not authorization. app.application is a read-only WSGI route and must still work.
    Browser buildQuery(state, changes={}) returns a query string: preserve current filters;
    clear stale cursor when status or limit changes, otherwise preserve it. No leading '?'.
    renderRows(rows) renders li items and escapes title text (& < > quotes).
    Only api.py, cursor.py and client.js may change. Inspect helpers if needed.
    """,
    {
        "contracts.py": "def sort_key(row):\n    return (row['created_at'], row['id'])\n",
        "api.py": """
        from contracts import sort_key
        from cursor import pack, unpack

        def list_response(rows, query):
            return 200, {'items': rows[:int(query.get('limit', 20))], 'next_cursor': None}
        """,
        "cursor.py": """
        import base64, json
        def pack(after, status):
            return base64.urlsafe_b64encode(json.dumps(list(after)).encode()).decode()
        def unpack(token):
            return json.loads(base64.urlsafe_b64decode(token))
        """,
        "client.js": """
        function buildQuery(state, changes={}) { return new URLSearchParams({...state,...changes}).toString(); }
        function renderRows(rows) { return rows.map(r=>`<li>${r.title}</li>`).join(''); }
        module.exports={buildQuery,renderRows};
        """,
        "app.py": """
        import json
        from urllib.parse import parse_qs
        from api import list_response
        ROWS=[{'id':1,'created_at':'2026-01-01','status':'open','title':'First'}]
        def application(environ, start_response):
            query={k:v[-1] for k,v in parse_qs(environ.get('QUERY_STRING',''),keep_blank_values=True).items()}
            status, body=list_response(ROWS,query)
            data=json.dumps(body).encode()
            start_response(f'{status} '+('OK' if status==200 else 'Bad Request'), [('Content-Type','application/json')])
            return [data]
        """,
    },
    {
        "cursor.py": """
        import base64, json
        def pack(after, status):
            return base64.urlsafe_b64encode(json.dumps({'after':list(after),'status':status},separators=(',',':')).encode()).decode().rstrip('=')
        def unpack(token):
            try:
                data=json.loads(base64.b64decode(token+'='*(-len(token)%4),altchars=b'-_',validate=True))
                after=data['after']; status=data['status']
                if not isinstance(after,list) or len(after)!=2 or not isinstance(after[0],str) or type(after[1]) is not int:
                    raise ValueError('invalid cursor key')
                if status not in ('','open','done'): raise ValueError('invalid cursor filter')
                return tuple(after),status
            except Exception as error:
                raise ValueError('invalid cursor') from error
        """,
        "api.py": """
        from contracts import sort_key
        from cursor import pack, unpack
        def list_response(rows, query):
            try:
                status=query.get('status','')
                if status not in ('','open','done'): raise ValueError('status')
                raw=query.get('limit',20)
                if isinstance(raw,bool): raise ValueError('limit')
                limit=int(raw)
                if str(raw)!=str(limit) or not 1<=limit<=50: raise ValueError('limit')
                selected=sorted((r for r in rows if not status or r['status']==status),key=sort_key)
                token=query.get('cursor')
                if token:
                    after,binding=unpack(token)
                    if binding!=status: raise ValueError('cursor filter')
                    selected=[r for r in selected if sort_key(r)>after]
                page=selected[:limit]
                next_cursor=pack(sort_key(page[-1]),status) if len(selected)>limit else None
                return 200,{'items':page,'next_cursor':next_cursor}
            except (ValueError,TypeError,KeyError,OverflowError):
                return 400,{'error':'invalid query'}
        """,
        "client.js": """
        function buildQuery(state,changes={}) {
          const next={...state,...changes};
          if((Object.hasOwn(changes,'status')&&changes.status!==state.status)||(Object.hasOwn(changes,'limit')&&changes.limit!==state.limit)) delete next.cursor;
          const p=new URLSearchParams(); for(const [k,v] of Object.entries(next)) if(v!==null&&v!==undefined&&v!=='') p.set(k,String(v)); return p.toString();
        }
        function escape(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
        function renderRows(rows){return rows.map(r=>`<li>${escape(r.title)}</li>`).join('');}
        module.exports={buildQuery,renderRows};
        """,
    },
    """
    from api import list_response
    rows=[{'id':1,'created_at':'a','status':'open','title':'one'}]
    status,body=list_response(rows,{'limit':'1'})
    assert status==200 and body['items']==rows and body['next_cursor'] is None
    from app import application
    headers=[]; assert b'items' in b''.join(application({'QUERY_STRING':''},lambda *v:headers.append(v)))
    assert headers[0][0].startswith('200')
    """ + node("const c=require('./client.js');if(!c.buildQuery({limit:2}).includes('limit=2'))throw Error('query');"),
    """
    from api import list_response
    import copy
    rows=[{'id':i,'created_at':'same','status':'open' if i%2 else 'done','title':str(i)} for i in [4,1,3,2,5]]
    before=copy.deepcopy(rows); got=[]; query={'limit':'1','status':'open'}
    for _ in range(5):
        status,body=list_response(rows,query); assert status==200
        got.extend(r['id'] for r in body['items'])
        if body['next_cursor'] is None: break
        query={**query,'cursor':body['next_cursor']}
    assert got==[1,3,5] and rows==before
    token=list_response(rows,{'limit':'1','status':'open'})[1]['next_cursor']
    assert list_response(rows,{'cursor':token,'status':'done'})[0]==400
    for bad in ({'limit':True},{'limit':'0'},{'limit':'51'},{'limit':'bad'},{'cursor':'%%%bad'},{'status':'unknown'}):
        assert list_response(rows,bad)[0]==400,bad
    """ + node("const a=require('assert'),c=require('./client.js');const state={status:'open',limit:2,cursor:'opaque'};a(!c.buildQuery(state,{status:'done'}).includes('cursor='));a(c.buildQuery(state,{}).includes('cursor=opaque'));a(!c.buildQuery(state,{limit:3}).includes('cursor='));const s=c.renderRows([{title:'<img x=\"x\">&'}]);a(!s.includes('<img')&&s.includes('&lt;')&&s.includes('&amp;'));a.equal(state.cursor,'opaque');"),
)


IDEMPOTENCY = case(
    "sqlite_idempotency", "SQLite idempotent submission",
    """
    Jobs(path).submit(title,request_id) returns (status,body).
    Use normalization.normalize_title for title identity. Its actual keyword-only API and
    DEFAULT_POLICY are in committed normalization.py; inspect and integrate with that API.
    A valid title is a nonempty string at most 120 normalized characters; request_id is a
    nonempty string at most 64 characters. Invalid input -> 400, no database mutation.
    A new request returns 201 and {'id':positive_int,'title':normalized_title}.
    The same key and normalized title returns 200 and the SAME id, including across
    process/connection restart and concurrent requests. Same key with different normalized
    title returns 409 without creating a row or changing the original job.
    api.handle(payload,store) validates an object, does not mutate payload and preserves
    these HTTP-like statuses. Only store.py and api.py may change. Use parameterized SQL.
    """,
    {
        "normalization.py": "import unicodedata\nDEFAULT_POLICY={'unicode_form':'NFC','collapse_whitespace':True}\ndef normalize_title(value, *, policy):\n    value=unicodedata.normalize(policy['unicode_form'],value)\n    return ' '.join(value.split()) if policy['collapse_whitespace'] else value\n",
        "store.py": """
        import sqlite3
        from normalization import DEFAULT_POLICY, normalize_title
        class Jobs:
            def __init__(self,path):
                self.path=str(path)
                with sqlite3.connect(self.path,timeout=5) as c:
                    c.execute('CREATE TABLE IF NOT EXISTS jobs(id INTEGER PRIMARY KEY,title TEXT NOT NULL,request_id TEXT UNIQUE NOT NULL)')
            def submit(self,title,request_id):
                with sqlite3.connect(self.path,timeout=5) as c:
                    c.execute('INSERT OR REPLACE INTO jobs(title,request_id) VALUES (?,?)',(title,request_id))
                    row=c.execute('SELECT id,title FROM jobs WHERE request_id=?',(request_id,)).fetchone()
                return 201,{'id':row[0],'title':row[1]}
        """,
        "api.py": "def handle(payload,store):\n    return store.submit(payload['title'],payload['request_id'])\n",
    },
    {
        "store.py": """
        import sqlite3
        from normalization import DEFAULT_POLICY, normalize_title
        class Jobs:
            def __init__(self,path):
                self.path=str(path)
                with sqlite3.connect(self.path,timeout=5) as c:
                    c.execute('CREATE TABLE IF NOT EXISTS jobs(id INTEGER PRIMARY KEY,title TEXT NOT NULL,request_id TEXT UNIQUE NOT NULL)')
            def submit(self,title,request_id):
                if not isinstance(title,str) or not isinstance(request_id,str): return 400,{'error':'invalid input'}
                title=normalize_title(title,policy=DEFAULT_POLICY)
                if not 0<len(title)<=120 or not 0<len(request_id)<=64 or not request_id.strip(): return 400,{'error':'invalid input'}
                with sqlite3.connect(self.path,timeout=5) as c:
                    c.execute('BEGIN IMMEDIATE')
                    row=c.execute('SELECT id,title FROM jobs WHERE request_id=?',(request_id,)).fetchone()
                    if row:
                        if row[1]!=title: return 409,{'error':'conflicting request'}
                        return 200,{'id':row[0],'title':row[1]}
                    result=c.execute('INSERT INTO jobs(title,request_id) VALUES (?,?)',(title,request_id))
                    return 201,{'id':result.lastrowid,'title':title}
        """,
        "api.py": """
        def handle(payload,store):
            if not isinstance(payload,dict): return 400,{'error':'invalid input'}
            return store.submit(payload.get('title'),payload.get('request_id'))
        """,
    },
    """
    from store import Jobs
    from api import handle
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        s,b=handle({'title':'first','request_id':'r'},Jobs(d+'/jobs.db'))
        assert s==201 and b['title']=='first' and b['id']>0
    """,
    """
    from store import Jobs
    from api import handle
    import sqlite3,tempfile,copy
    from concurrent.futures import ThreadPoolExecutor
    with tempfile.TemporaryDirectory() as d:
        path=d+'/jobs.db'; store=Jobs(path); payload={'title':' Cafe\u0301  task ','request_id':'same'}; before=copy.deepcopy(payload)
        first=handle(payload,store); assert first[0]==201 and first[1]['title']=='Café task'
        assert handle({'title':'Café task','request_id':'same'},Jobs(path))==(200,first[1])
        assert handle({'title':'different','request_id':'same'},store)[0]==409
        assert payload==before
        for bad in ({},{'title':'','request_id':'x'},{'title':'x','request_id':None},[],{'title':'x'*121,'request_id':'x'},{'title':'x','request_id':' '*65+'id'}):
            assert handle(bad,store)[0]==400
        with ThreadPoolExecutor(max_workers=8) as pool:
            results=list(pool.map(lambda _:Jobs(path).submit('parallel','parallel'),range(8)))
        assert sum(status==201 for status,_ in results)==1
        assert {status for status,_ in results}<={200,201}
        assert len({body['id']for _,body in results})==1
        with sqlite3.connect(path) as c: assert c.execute('SELECT count(*) FROM jobs').fetchone()[0]==2
    """,
)


RECOVERY = case(
    "manual_checkpoint", "Manual checkpoint recovery + browser controls",
    """
    Preserve the public functions boot(run), review(run), resume(run,token,confirmed=False).
    Input run has id, revision, checkpoint, state, done (node ids), attempts (node->count).
    boot returns a reminder dict with automatic_resume=False and MUST NOT execute/mutate.
    review accepts only interrupted runs, returns a deep copy in reviewed state with a
    review_token bound to CURRENT id, revision and checkpoint; it does not start a node.
    resume requires reviewed state, the matching current token and confirmed is True.
    Reject stale tokens, changed checkpoint/revision, tokens from other tasks and replays.
    Reject a checkpoint already in done. Explicit resume increments ONLY that checkpoint's
    attempt, appends it to done, returns completed state, and leaves input unchanged.
    Browser actions(run,confirmed=false) returns review/resume booleans: review only for
    interrupted; resume only for reviewed plus explicit true confirmation and a token.
    Only workflow.py and client.js may change. All state transitions are data in this
    isolated example; do not operate the real Daedalus service or host processes.
    """,
    {
        "workflow.py": """
        import copy
        def boot(run):
            return resume(run,'',True)
        def review(run):
            result=copy.deepcopy(run); result['state']='reviewed'; result['review_token']='reviewed'; return result
        def resume(run,token,confirmed=False):
            run['attempts'][run['checkpoint']]+=1; run['done'].append(run['checkpoint']); run['state']='completed'; return run
        """,
        "client.js": "function actions(run,confirmed=false){return {review:true,resume:run.state!=='completed'};}\nmodule.exports={actions};\n",
    },
    {
        "workflow.py": """
        import copy,hashlib,json
        def _review_token(run):
            return hashlib.sha256(json.dumps([run['id'],run['revision'],run['checkpoint']],separators=(',',':')).encode()).hexdigest()
        def boot(run):
            return {'automatic_resume':False,'message':'Review checkpoint before explicit resume'}
        def review(run):
            if run['state']!='interrupted': raise ValueError('review requires interruption')
            result=copy.deepcopy(run); result['state']='reviewed'; result['review_token']=_review_token(run); return result
        def resume(run,token,confirmed=False):
            if run['state']!='reviewed' or confirmed is not True or token!=run.get('review_token') or token!=_review_token(run) or run['checkpoint']in run['done']:
                raise ValueError('explicit current review required')
            result=copy.deepcopy(run); node=result['checkpoint']; result['attempts'][node]=result['attempts'].get(node,0)+1; result['done'].append(node); result['state']='completed'; return result
        """,
        "client.js": "function actions(run,confirmed=false){return {review:run.state==='interrupted',resume:run.state==='reviewed'&&confirmed===true&&Boolean(run.review_token)};}\nmodule.exports={actions};\n",
    },
    """
    from workflow import boot,review
    run={'id':'r','revision':1,'checkpoint':'b','state':'interrupted','done':['a'],'attempts':{'a':1,'b':0}}
    assert boot(run)['automatic_resume'] is False
    assert review(run)['state']=='reviewed'
    """ + node("const a=require('assert'),c=require('./client.js');a(c.actions({state:'interrupted'}).review);"),
    """
    from workflow import boot,review,resume
    import copy
    run={'id':'r','revision':1,'checkpoint':'b','state':'interrupted','done':['a'],'attempts':{'a':1,'b':0}}
    before=copy.deepcopy(run); boot(run); checked=review(run); assert run==before and checked['attempts']==before['attempts']
    def refused(value,t,flag):
        prior=copy.deepcopy(value)
        try: resume(value,t,flag)
        except ValueError: pass
        else: raise AssertionError('resume must be refused')
        assert value==prior
    refused(checked,checked['review_token'],False); refused(checked,'wrong',True)
    refused(checked,checked['review_token'],1); refused(checked,checked['review_token'],'yes')
    refused({**checked,'revision':2},checked['review_token'],True)
    refused({**checked,'checkpoint':'c'},checked['review_token'],True)
    refused({**checked,'id':'other'},checked['review_token'],True)
    done=resume(checked,checked['review_token'],True)
    assert done['attempts']=={'a':1,'b':1} and done['done']==['a','b'] and done['state']=='completed'
    assert checked['attempts']['b']==0
    assert resume(checked,token=checked['review_token'],confirmed=True)['state']=='completed'
    refused(done,checked['review_token'],True)
    """ + node("const a=require('assert'),c=require('./client.js');const r={state:'reviewed',review_token:'current'};a(!c.actions(r).resume);a(!c.actions(r,1).resume);a(c.actions(r,true).resume);a(!c.actions({state:'completed',review_token:'current'},true).resume);a(!c.actions({state:'running'}).review);"),
)


RETRIEVAL = case(
    "versioned_context", "Versioned retrieval citations + browser rendering",
    """
    retrieval.select_context(hits,repo,commit,limit=3) returns a list of citations.
    Each hit has repo,commit,path,line_start,line_end,text,score; multiple recall channels
    can return the same chunk. Admit only the EXACT requested repo and commit; never mix
    stale versions or another project. Valid paths are relative POSIX paths: reject absolute,
    backslash, colon, empty/./.. segments and hidden segments such as .env or .git.
    Require nonempty text, positive integer line_start and line_end>=line_start, and finite
    numeric score (not bool). Skip invalid hits, do not mutate input. limit must be int 1..5.
    Deduplicate by repo/commit/path/line_start/line_end/text, keep the maximum channel score.
    Rank by descending score, then path, line_start, line_end and text for stable ties.
    Return the fields above plus digest = SHA256 of compact sorted-key ensure_ascii=False
    JSON of repo,commit,path,line_start,line_end,text ONLY (excluding score).
    Browser renderCitations(rows) returns HTML with escaped path/text and local #source links
    containing encoded path and commit; source paths must never become external URLs.
    Only retrieval.py and client.js may change.
    """,
    {
        "retrieval.py": """
        def select_context(hits,repo,commit,limit=3):
            return sorted(hits,key=lambda h:-h['score'])[:limit]
        """,
        "client.js": "function renderCitations(rows){return rows.map(r=>`<a href=\"${r.path}\">${r.path}: ${r.text}</a>`).join('');}\nmodule.exports={renderCitations};\n",
    },
    {
        "retrieval.py": """
        import hashlib,json,math
        def select_context(hits,repo,commit,limit=3):
            if type(limit)is not int or not 1<=limit<=5: raise ValueError('limit')
            chosen={}
            for h in hits:
                if not isinstance(h,dict) or h.get('repo')!=repo or h.get('commit')!=commit: continue
                p=h.get('path'); body=h.get('text'); start=h.get('line_start'); end=h.get('line_end'); score=h.get('score')
                if not isinstance(p,str) or not p or '\\\\'in p or ':'in p or any(not s or s.startswith('.')for s in p.split('/')): continue
                if not isinstance(body,str) or not body.strip() or type(start)is not int or type(end)is not int or start<1 or end<start: continue
                if type(score)not in(int,float) or not math.isfinite(score): continue
                key=(repo,commit,p,start,end,body)
                if key in chosen and chosen[key]['score']>=score: continue
                fields=dict(zip(('repo','commit','path','line_start','line_end','text'),key))
                fields['digest']=hashlib.sha256(json.dumps(fields,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
                chosen[key]={**fields,'score':score}
            return sorted(chosen.values(),key=lambda h:(-h['score'],h['path'],h['line_start'],h['line_end'],h['text']))[:limit]
        """,
        "client.js": """
        function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
        function renderCitations(rows){return rows.map(r=>`<a href="#source?path=${encodeURIComponent(r.path)}&amp;commit=${encodeURIComponent(r.commit)}">${esc(r.path)}: ${esc(r.text)}</a>`).join('');}
        module.exports={renderCitations};
        """,
    },
    """
    from retrieval import select_context
    h={'repo':'r','commit':'v1','path':'docs/a.md','line_start':1,'line_end':2,'text':'reference','score':1}
    assert select_context([h],'r','v1')[0]['path']=='docs/a.md'
    """ + node("const a=require('assert'),c=require('./client.js');a(c.renderCitations([{path:'docs/a.md',commit:'v1',text:'reference'}]).includes('reference'));"),
    """
    from retrieval import select_context
    import copy,json,hashlib,math
    h={'repo':'r','commit':'v1','path':'docs/a.md','line_start':1,'line_end':2,'text':'新规则','score':2}
    data=[h,{**h,'score':5},{**h,'commit':'old','score':999},{**h,'repo':'other','score':999},{**h,'path':'../private','score':999},{**h,'path':'.env','score':999},{**h,'path':'javascript:bad','score':999},{**h,'score':float('nan')},{**h,'line_start':True},{**h,'path':'docs/b.md','score':3}]
    data += [{**h,'path':path,'score':999}for path in ['/private','docs//a.md','docs/./a.md','docs/.private','a'+chr(92)+'b.md']]
    before=copy.deepcopy(data); rows=select_context(data,'r','v1',5)
    assert [r['path']for r in rows]==['docs/a.md','docs/b.md'] and rows[0]['score']==5
    assert len(data)==len(before) and h['score']==2
    fields={k:rows[0][k]for k in ('repo','commit','path','line_start','line_end','text')}
    assert rows[0]['digest']==hashlib.sha256(json.dumps(fields,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
    assert select_context([{**h,'score':3},{**h,'path':'docs/b.md','score':3}],'r','v1')[0]['path']=='docs/a.md'
    for limit in [True,0,6]:
        try: select_context([h],'r','v1',limit)
        except ValueError: pass
        else: raise AssertionError('limit')
    """ + node("const a=require('assert'),c=require('./client.js');const s=c.renderCitations([{path:'docs/a.md',commit:'v1',text:'<img src=x>&'}]);a(s.includes('#source?')&&s.includes('path=docs%2Fa.md')&&!s.includes('<img')&&s.includes('&amp;'));"),
)


BILLING = case(
    "usage_export", "Usage accounting + safe CSV and browser summary",
    """
    billing.aggregate(records) uses Decimal, no real provider prices: rates are fixed test
    units per million tokens. Each record has prompt_tokens, completion_tokens,
    cached_prompt_tokens (default 0), input_rate, cache_rate, output_rate.
    Token values must be nonnegative int (not bool); cached<=prompt. Missing/None prompt or
    completion means unknown usage: increment unknown_requests and exclude that entire
    record from known tokens and estimated cost; validate any provided token fields first.
    Known usage with cached_prompt_tokens=None is also unknown. Rates must be finite,
    nonnegative decimal strings, else ValueError. Return input_tokens, output_tokens,
    cached_tokens, known_tokens=input+output, unknown_requests, estimated_cost as a string
    rounded HALF_UP to 6 decimal places, with uncached input, cached input and output each
    priced once. Never treat unknown usage as a known zero-cost request or mutate records.
    exports.export_csv(rows) writes provider,prompt_tokens,completion_tokens headers. Preserve
    Unicode and unknown token cells as blank; defend provider cells against spreadsheet
    formulas: prefix apostrophe if the first non-whitespace character is = + - or @.
    Browser usageText(report) must show both known_tokens and unknown_requests, including
    unknown when known tokens are zero. renderProviders(rows) escapes provider labels.
    Only billing.py, exports.py, client.js may change.
    """,
    {
        "billing.py": """
        def aggregate(records):
            tokens=sum((r.get('prompt_tokens')or 0)+(r.get('completion_tokens')or 0)for r in records)
            return {'known_tokens':tokens,'input_tokens':tokens,'output_tokens':0,'cached_tokens':0,'unknown_requests':0,'estimated_cost':'0.000000'}
        """,
        "exports.py": """
        import csv,io
        def export_csv(rows):
            out=io.StringIO(); writer=csv.writer(out); writer.writerow(['provider','prompt_tokens','completion_tokens'])
            for r in rows: writer.writerow([r.get('provider',''),r.get('prompt_tokens')or 0,r.get('completion_tokens')or 0])
            return out.getvalue()
        """,
        "client.js": "function usageText(r){return String(r.known_tokens)+' tokens';}\nfunction renderProviders(rows){return rows.map(r=>`<span>${r.provider}</span>`).join('');}\nmodule.exports={usageText,renderProviders};\n",
    },
    {
        "billing.py": """
        from decimal import Decimal,InvalidOperation,ROUND_HALF_UP
        def aggregate(records):
            report={'input_tokens':0,'output_tokens':0,'cached_tokens':0,'known_tokens':0,'unknown_requests':0}; cost=Decimal(0)
            for r in records:
                p,o,c=r.get('prompt_tokens'),r.get('completion_tokens'),r.get('cached_prompt_tokens',0)
                for n in (p,o,c):
                    if n is not None and (type(n)is not int or n<0): raise ValueError('invalid usage')
                if p is not None and c is not None and c>p: raise ValueError('cache exceeds input')
                if p is None or o is None or c is None: report['unknown_requests']+=1; continue
                rates=[]
                for key in ('input_rate','cache_rate','output_rate'):
                    try:
                        raw=r[key]
                        if not isinstance(raw,str): raise ValueError('rate string required')
                        rate=Decimal(raw)
                        if not rate.is_finite() or rate<0: raise ValueError('invalid rate')
                        rates.append(rate)
                    except (InvalidOperation,KeyError) as error: raise ValueError('invalid rate')from error
                report['input_tokens']+=p; report['output_tokens']+=o; report['cached_tokens']+=c; report['known_tokens']+=p+o
                cost+=((p-c)*rates[0]+c*rates[1]+o*rates[2])/Decimal(1000000)
            report['estimated_cost']=str(cost.quantize(Decimal('0.000001'),rounding=ROUND_HALF_UP)); return report
        """,
        "exports.py": """
        import csv,io
        def export_csv(rows):
            out=io.StringIO(newline=''); writer=csv.writer(out); writer.writerow(['provider','prompt_tokens','completion_tokens'])
            for r in rows:
                label=str(r.get('provider',''))
                if label.lstrip().startswith(('=','+','-','@')): label="'"+label
                writer.writerow([label,''if r.get('prompt_tokens')is None else r['prompt_tokens'],''if r.get('completion_tokens')is None else r['completion_tokens']])
            return out.getvalue()
        """,
        "client.js": """
        function usageText(r){return `${r.known_tokens} tokens · ${r.unknown_requests} unknown`;}
        function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
        function renderProviders(rows){return rows.map(r=>`<span>${esc(r.provider)}</span>`).join('');}
        module.exports={usageText,renderProviders};
        """,
    },
    """
    from billing import aggregate
    report=aggregate([{'prompt_tokens':10,'completion_tokens':5,'input_rate':'1','cache_rate':'0.1','output_rate':'2'}])
    assert report['known_tokens']==15
    from exports import export_csv
    assert 'provider' in export_csv([])
    """ + node("const c=require('./client.js');if(!c.usageText({known_tokens:15,unknown_requests:0}).includes('15'))throw Error('summary');"),
    """
    from billing import aggregate
    from exports import export_csv
    import copy,csv,io
    base={'prompt_tokens':1000000,'completion_tokens':250000,'cached_prompt_tokens':400000,'input_rate':'2','cache_rate':'0.5','output_rate':'4'}
    records=[base,{'prompt_tokens':None,'completion_tokens':5}]; before=copy.deepcopy(records)
    result=aggregate(records)
    assert result['known_tokens']==1250000 and result['unknown_requests']==1 and result['cached_tokens']==400000
    assert result['input_tokens']==1000000 and result['output_tokens']==250000
    assert result['estimated_cost']=='2.400000' and records==before
    assert aggregate([{'prompt_tokens':None,'completion_tokens':None}])['unknown_requests']==1
    tiny={**base,'prompt_tokens':1,'completion_tokens':0,'cached_prompt_tokens':0,'input_rate':'0.5'}
    assert aggregate([tiny])['estimated_cost']=='0.000001'
    for bad in ({'prompt_tokens':-1},{'completion_tokens':True},{'cached_prompt_tokens':1000001},{'input_rate':'NaN'},{'output_rate':'-1'}):
        try: aggregate([{**base,**bad}])
        except ValueError: pass
        else: raise AssertionError('invalid accounting')
    rows=[{'provider':' =SUM(A1)','prompt_tokens':None,'completion_tokens':0},{'provider':'中文,服务','prompt_tokens':1,'completion_tokens':2}]
    parsed=list(csv.reader(io.StringIO(export_csv(rows))))
    assert parsed[1]==["' =SUM(A1)",'','0'] and parsed[2][0]=='中文,服务'
    """ + node("const a=require('assert'),c=require('./client.js');const s=c.usageText({known_tokens:0,unknown_requests:3});a(s.includes('0')&&s.includes('3'));a(!c.renderProviders([{provider:'<img x=1>&'}]).includes('<img'));"),
)


CONFIG = case(
    "config_migration", "Private atomic configuration migration + CLI reminders",
    """
    config.migrate(data) validates and returns a new version-2 object, never mutating input.
    v1 fields: version=1, endpoint, model, timeout(default 60), api_key(optional),
    credential_ref(optional), notes(list of strings), interrupted_tasks(list of strings).
    v2 contains version=2, connection={endpoint,model,timeout_sec}, credential_ref,
    requires_credential(bool), notes, interrupted_tasks. Omit api_key and all unknown fields.
    Preserve credential_ref (or None), notes and interrupted_tasks. requires_credential is
    true if no reference exists: legacy plaintext is NOT a recoverable saved credential.
    Validate v2 too. Endpoint is an absolute HTTPS URL, or HTTP for localhost/127.0.0.1/::1
    only; no userinfo, query or fragment; remove trailing slashes without deleting paths.
    Model must be a nonempty string; timeout integer 1..300, not bool; reject unknown version.
    save(path,data) validates BEFORE touching existing contents; write via same-directory
    temporary file, mode 0600 then atomic os.replace. Clean temporary files on failure.
    cli.startup(path) loads/sanitizes settings and returns a dict with automatic_resume=False,
    requires_credential and reminders(list including every interrupted task). No task starts.
    cli.status(path) returns a JSON string of sanitized v2 configuration, without plaintext
    credentials even if reading a legacy file. Only config.py and cli.py may change.
    """,
    {
        "config.py": """
        import json
        from pathlib import Path
        def migrate(data): return dict(data)
        def save(path,data): Path(path).write_text(json.dumps(data))
        """,
        "cli.py": """
        import json
        from pathlib import Path
        def startup(path): return {'automatic_resume':True,'requires_credential':False,'reminders':[]}
        def status(path): return Path(path).read_text()
        """,
    },
    {
        "config.py": """
        import json,os,tempfile
        from pathlib import Path
        from urllib.parse import urlsplit
        def migrate(data):
            if not isinstance(data,dict) or type(data.get('version'))is not int or data['version']not in(1,2): raise ValueError('version')
            c=data if data['version']==1 else data.get('connection')
            if not isinstance(c,dict): raise ValueError('connection')
            endpoint=c.get('endpoint'); model=c.get('model'); timeout=c.get('timeout',60)if data['version']==1 else c.get('timeout_sec',60)
            if not isinstance(endpoint,str): raise ValueError('endpoint')
            try:
                url=urlsplit(endpoint); port=url.port
            except ValueError as error: raise ValueError('endpoint')from error
            if not url.hostname or url.username is not None or url.password is not None or url.query or url.fragment or not(url.scheme=='https'or(url.scheme=='http'and url.hostname in('localhost','127.0.0.1','::1'))): raise ValueError('endpoint')
            if not isinstance(model,str)or not model.strip()or type(timeout)is not int or not 1<=timeout<=300: raise ValueError('connection')
            ref=data.get('credential_ref')
            if ref is not None and(not isinstance(ref,str)or not ref.strip()): raise ValueError('reference')
            notes=data.get('notes',[]); tasks=data.get('interrupted_tasks',[])
            if any(not isinstance(xs,list)or any(not isinstance(v,str)for v in xs)for xs in(notes,tasks)): raise ValueError('notes')
            return {'version':2,'connection':{'endpoint':endpoint.rstrip('/'),'model':model.strip(),'timeout_sec':timeout},'credential_ref':ref,'requires_credential':not bool(ref),'notes':list(notes),'interrupted_tasks':list(tasks)}
        def save(path,data):
            clean=migrate(data); path=Path(path); temporary=None
            try:
                fd,temporary=tempfile.mkstemp(prefix='.'+path.name+'-',dir=path.parent)
                with os.fdopen(fd,'w',encoding='utf-8')as stream:
                    os.fchmod(stream.fileno(),0o600); json.dump(clean,stream,ensure_ascii=False); stream.flush(); os.fsync(stream.fileno())
                os.replace(temporary,path); temporary=None
            finally:
                if temporary is not None: Path(temporary).unlink(missing_ok=True)
        """,
        "cli.py": """
        import json
        from pathlib import Path
        from config import migrate
        def startup(path):
            value=migrate(json.loads(Path(path).read_text()))
            return {'automatic_resume':False,'requires_credential':value['requires_credential'],'reminders':['Review before explicit resume: '+task for task in value['interrupted_tasks']]}
        def status(path): return json.dumps(migrate(json.loads(Path(path).read_text())),ensure_ascii=False)
        """,
    },
    """
    from config import migrate,save
    from cli import startup
    import tempfile
    from pathlib import Path
    legacy={'version':1,'endpoint':'https://example.invalid/v1/','model':'demo','notes':[],'interrupted_tasks':['task-1']}
    assert migrate(legacy)['version']==2
    with tempfile.TemporaryDirectory()as d:
        p=Path(d)/'settings.json'; save(p,legacy); assert startup(p)['automatic_resume']is False
    """,
    """
    from config import migrate,save
    from cli import startup,status
    import copy,tempfile,json,os,stat
    from pathlib import Path
    from unittest.mock import patch
    legacy={'version':1,'endpoint':'https://example.invalid/v1///','model':' demo ','timeout':75,'api_key':'private-value-for-local-test','notes':['keep'],'interrupted_tasks':['task-a','task-b']}; before=copy.deepcopy(legacy)
    clean=migrate(legacy); assert legacy==before and clean['requires_credential']is True and 'api_key'not in clean
    assert clean['connection']=={'endpoint':'https://example.invalid/v1','model':'demo','timeout_sec':75}
    assert migrate({**legacy,'credential_ref':'keychain-ref'})['requires_credential']is False
    assert migrate(clean)==clean
    for bad in ({'version':9},{'timeout':True},{'endpoint':'http://remote.invalid'},{'endpoint':'https://name:pass@example.invalid'},{'endpoint':'https://example.invalid?secret=x'},{'notes':'bad'}):
        try: migrate({**legacy,**bad})
        except ValueError: pass
        else: raise AssertionError('invalid config')
    with tempfile.TemporaryDirectory()as d:
        p=Path(d)/'settings.json'; p.write_text(json.dumps(legacy)); value=status(p); assert 'private-value-for-local-test'not in value and 'api_key'not in value
        reminder=startup(p); assert reminder['automatic_resume']is False and all(any(t in s for s in reminder['reminders'])for t in ['task-a','task-b'])
        save(p,legacy); stored=p.read_text(); assert json.loads(stored)==clean and stat.S_IMODE(p.stat().st_mode)==0o600
        try: save(p,{**legacy,'version':0})
        except ValueError: pass
        else: raise AssertionError('validation before mutation')
        assert p.read_text()==stored
        with patch('config.os.replace',side_effect=OSError('controlled fault')):
            try: save(p,legacy)
            except OSError: pass
            else: raise AssertionError('fault expected')
        assert p.read_text()==stored and sorted(x.name for x in Path(d).iterdir())==['settings.json']
    """,
)


ENGINEERING_CASES = (PAGINATION, IDEMPOTENCY, RECOVERY, RETRIEVAL, BILLING, CONFIG)
