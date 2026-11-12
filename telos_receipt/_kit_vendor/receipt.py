"""Standalone offline H0a receipt reader. Standard library and the sibling witness module; no host/runtime imports.

Ordinary hashes check byte consistency. They do not authenticate an author or
prove that an honest or comprehensive observation path produced these events.

Every report carries one authenticity statement, "authenticity": "WITNESSED" or "NOT_WITNESSED" (h0a/witness.py),
with `witness` (key fingerprint, row, time) or `witness_reason`. check_receipt reads receipt bytes alone, so its
report is the state of a receipt with no witness row beside it; check_record reads the receipt file and the
witness.json beside it, and the command prints that state's sentence once on stderr beside its JSON. check_record's
report also carries `reading`: {"state": ...}, the state of the reading.json beside the receipt (h0a/reading.py),
which is READING_WITNESSED only when this record's Witness row names the digest of that file's bytes. Errors are the
reader's own reason phrases; an error Python raises while reading the record is reported as 'malformed record',
never its message.

The command: python -I h0a/receipt.py [--require-witnessed] <receipt.json>. It exits 0 when the structure is VALID
and 2 otherwise (INVALID, an unreadable receipt, or any other argument shape). With --require-witnessed, given
first, it exits 0 only when the structure is VALID and the record is WITNESSED, 1 when the structure is VALID and
the record is NOT_WITNESSED, and 2 as before. The flag changes the exit code only: stdout and stderr are the same.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

try:
    from h0a import witness
except ImportError:  # run as a script under -I: the script directory is not on sys.path, so load the sibling by path
    import importlib.util
    _spec=importlib.util.spec_from_file_location('witness',Path(__file__).with_name('witness.py'))
    witness=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(witness)

PROFILE='h0a/read-excerpt-v1'
MAX_BYTES=1048576
MALFORMED='malformed record'
REQUIRE_WITNESSED='--require-witnessed'  # the command's one flag: NOT_WITNESSED then exits 1


class _Refused(ValueError):
    """A check of this reader failed; its one argument is the reason phrase that reaches the report."""

# Independently declared checker profile, not imported from the host validator.
PROFILE_LIMITS={'max_agents':1,'max_inflight':1,'max_attempts':8,
                'max_dispatches':2,'approval_seconds':60,'export_limit':1048576}
CONFIG_FIELDS={'work_id','purpose_hash','job','operator','schema','revision','contact','limits',
    'execution_enabled','mode','tools','documents','providers','spend_limit','max_agents',
    'max_inflight','max_attempts','max_dispatches','require_approval','approval_seconds',
    'allow_max','review_max','detector_version','preprocessing_version','band_version',
    'policy_version','runtime_version','orchestration_version','tool_version','privacy','export_limit'}


def _prior_action_closed(terminal,post_checked):
    """Independent checker policy over reduced states; transitions validate separately."""
    return terminal in ('COMPLETED','FAILED','REFUSED') and (terminal=='REFUSED' or post_checked)


def _check_profile_config(cfg,require):
    require(type(cfg) is dict and set(cfg)==CONFIG_FIELDS,'configuration fields outside profile')
    require(type(cfg['schema']) is int and cfg['schema']==1,'configuration schema')
    for name in ('work_id','revision','job','operator','contact','limits','detector_version',
                 'preprocessing_version','band_version','policy_version','runtime_version',
                 'orchestration_version','tool_version'):
        require(type(cfg[name]) is str and bool(cfg[name].strip()),'invalid configuration '+name)
    purpose=cfg['purpose_hash']
    require(type(purpose) is str and len(purpose)==64 and all(c in '0123456789abcdef' for c in purpose),'purpose reference')
    for name in ('execution_enabled','require_approval'):
        require(type(cfg[name]) is bool,'invalid configuration switch')
    require(cfg['mode'] in ('ADVISORY','CONTROLLED'),'invalid authority mode')
    for name,allowed in [('tools',{'read_excerpt'}),('documents',{'doc-a','doc-b'}),('providers',set())]:
        values=cfg[name]
        require(type(values) is list and all(type(v) is str for v in values),'invalid grant list')
        require(len(values)==len(set(values)) and set(values)<=allowed,'grant outside profile')
    for name,maximum in PROFILE_LIMITS.items():
        require(type(cfg[name]) is int and 1<=cfg[name]<=maximum,'limit outside profile: '+name)
    require(type(cfg['spend_limit']) is int and cfg['spend_limit']==0,'spend outside profile')
    require(type(cfg['allow_max']) is int and type(cfg['review_max']) is int
            and 0<=cfg['allow_max']<cfg['review_max']<100,'invalid declared bands')
    require(cfg['privacy']=='synthetic-only','data outside profile')


def _bytes(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def segment_id(segment):return hashlib.sha256(_bytes(segment)).hexdigest()


def make_segment(events):
    # JSON round trip prevents later caller mutation of exported evidence.
    copied=json.loads(_bytes(events))
    return {'schema':1,'profile':PROFILE,'events':copied,'event_count':len(copied),
            'identity_assurance':'local-operator-asserted',
            'limitations':['synthetic contracts only; no Hermes/AGT integration',
                           'no semantic accuracy, authorship or universal observation proof']}


def _operator(segment):
    configured=[e['payload']['config'] for e in segment['events'] if e['kind']=='CONFIGURED']
    if not configured:raise ValueError('no configuration')
    return configured[-1]['operator']


def record_review(segment,operator,actor_kind,decision,reason,target):
    if (target!=segment_id(segment) or actor_kind!='human' or operator!=_operator(segment)
            or decision not in ('ACCEPT','HOLD','REJECT') or not isinstance(reason,str) or not reason.strip()):
        raise ValueError('invalid local asserted human review')
    return {'target_runtime_sha256':target,'operator':operator,'actor_kind':actor_kind,
            'decision':decision,'reason':reason,'identity_assurance':'local-operator-asserted',
            'observed_at':datetime.now(timezone.utc).isoformat()}


def export_receipt(events,review=None,*,limit=MAX_BYTES):
    segment=make_segment(events)
    if review:
        record_review(segment,review['operator'],review['actor_kind'],review['decision'],
                      review['reason'],review['target_runtime_sha256'])
    bundle={'schema':1,'runtime':segment,'runtime_sha256':segment_id(segment),'review':review}
    raw=_bytes(bundle)
    if len(raw)>min(limit,MAX_BYTES):raise ValueError('receipt exceeds export limit')
    return raw


def check_receipt(raw):
    report={'structure':'INVALID','coverage':'UNKNOWN','unknown_outcomes':[],
            'coverage_gaps':[],
            'identity_assurance':'unverified',**witness.fields(witness.NOT_REQUESTED),
            'human_review':'MISSING','errors':[]}
    def require(condition,message):
        if not condition:raise _Refused(message)
    def pairs(items):
        out={}
        for k,v in items:
            require(k not in out,'duplicate JSON field')
            out[k]=v
        return out
    try:
        require(type(raw) is bytes and len(raw)<=MAX_BYTES,'invalid/oversize input')
        bundle=json.loads(raw.decode('utf-8'),object_pairs_hook=pairs,
                          parse_constant=lambda _:(_ for _ in ()).throw(_Refused('nonfinite JSON')))
        require(type(bundle) is dict,'invalid bundle')
        if bundle.get('schema')!=1:
            report['structure']='UNSUPPORTED';return report
        require(set(bundle)=={'schema','runtime','runtime_sha256','review'},'bundle fields')
        segment=bundle['runtime']
        if segment.get('schema')!=1 or segment.get('profile')!=PROFILE:
            report['structure']='UNSUPPORTED';return report
        require(segment_id(segment)==bundle['runtime_sha256'],'runtime integrity mismatch')
        events=segment['events']
        require(type(events) is list and len(events)==segment['event_count'],'event count mismatch')
        require(segment['identity_assurance']=='local-operator-asserted','identity assurance unsupported')
        configs={};confirmed=set();agents={};actions={};dispatches=0;recorded_gaps=[]
        current=None
        required_event={'schema','kind','action_id','payload','work_id','revision',
                        'config_identity','source','observed_at','seq'}
        for seq,e in enumerate(events,1):
            require(set(e)==required_event and e['schema']==1 and type(e['seq']) is int and e['seq']==seq,'event schema/order')
            require(isinstance(e['source'],str) and isinstance(e['observed_at'],str),'observation metadata')
            kind,aid,p=e['kind'],e['action_id'],e['payload']
            require(type(p) is dict,'invalid event payload')
            if kind=='CONFIGURED':
                cfg=p['config'];identity=hashlib.sha256(_bytes(cfg)).hexdigest()
                _check_profile_config(cfg,require)
                require(cfg['schema']==1 and e['config_identity']==identity,'configuration mismatch')
                require(cfg['work_id']==e['work_id'] and cfg['revision']==e['revision'],'work reference mismatch')
                require(not configs or cfg['work_id']==current['work_id'],'multiple works')
                key=(cfg['work_id'],cfg['revision'])
                require(key not in configs,'duplicate configuration revision')
                configs[key]=cfg;current=cfg
                continue
            require(current is not None,'event without configuration')
            require((e['work_id'],e['revision'])==(current['work_id'],current['revision'])
                    and e['config_identity']==hashlib.sha256(_bytes(current)).hexdigest(),'stale event configuration')
            key=(e['work_id'],e['revision'])
            if kind=='CONFIGURATION_DECISION':
                require(p['actor_kind']=='human' and p['operator']==current['operator']
                        and p['identity_assurance']=='local-operator-asserted' and p['reason'].strip(),'invalid confirmation')
                require(p['decision'] in ('CONFIRM','REFUSE'),'invalid configuration decision')
                if p['decision']=='CONFIRM':confirmed.add(key)
                else:confirmed.discard(key)
            elif kind=='AGENT_ADMITTED':
                ctx=p['context'];agent=(key,ctx['agent_id'])
                require(key in confirmed and ctx['parent_id'] is None,'unconfirmed/nonroot agent')
                require(ctx['work_id']==key[0] and ctx['revision']==key[1],'agent work reference')
                require(agent not in agents and sum(k[0]==key for k in agents)<current['max_agents'],'agent limit/duplicate')
                require(p['lineage']==[ctx['agent_id']] and set(p['tools'])<=set(current['tools'])
                        and set(p['documents'])<=set(current['documents']) and not p['providers'] and p['spend_limit']==0,'agent grant expansion')
                agents[agent]=ctx
            elif kind=='ROUTE_REFUSED':
                require(aid is None,'route refusal cannot imply dispatch')
            elif kind=='ADMISSION_REFUSED':
                require(aid is None and p['reason'] in ('MAX_INFLIGHT','DISPATCH_UNCERTAIN'),'invalid admission refusal')
            elif kind=='EVIDENCE_GAP':
                require(aid is None and isinstance(p['reason'],str),'invalid gap marker')
                recorded_gaps.append(p['reason'])
            elif kind=='ATTEMPTED':
                c=p['candidate']
                require(all(_prior_action_closed(a['terminal'],a['stage']=='POST_CHECK')
                            for a in actions.values()),'overlapping action lifecycle')
                require(aid not in actions and c['action_id']==aid,'duplicate/conflicting action')
                require(key in confirmed and (key,c['agent_id']) in agents,'unadmitted action')
                require((c['work_id'],c['revision'])==key and c['config_identity']==e['config_identity'],'candidate reference')
                require(c['tool']=='read_excerpt','unsupported tool')
                args=json.loads(c['arguments_json'],object_pairs_hook=pairs)
                require(args in ({'document_id':'doc-a'},{'document_id':'doc-b'}),'unsupported arguments')
                require(_bytes(args).decode()==c['arguments_json'],'noncanonical arguments')
                require(hashlib.sha256(_bytes(c)).hexdigest()==p['digest'],'candidate digest mismatch')
                require(len(actions)<current['max_attempts'],'attempt budget exceeded')
                actions[aid]={'stage':'ATTEMPTED','candidate':c,'cfg':current,'measurement':None,
                              'approval':None,'intent':False,'terminal':None}
            else:
                require(aid in actions,'event without action')
                a=actions[aid]
                require(a['candidate']['revision']==e['revision'],'action revision changed')
                if kind=='EVALUATED':
                    require(a['stage']=='ATTEMPTED','evaluation ordering')
                    require(p['label'] in ('ALLOW','REVIEW','DENY','UNKNOWN'),'invalid label')
                    score=p['score']
                    if score is None:expected='UNKNOWN'
                    else:
                        require(type(score) is int and 0<=score<=100,'invalid integer score')
                        expected=('ALLOW' if score<=a['cfg']['allow_max'] else
                                  'REVIEW' if score<=a['cfg']['review_max'] else 'DENY')
                    require(p['label']==expected,'score and band label disagree')
                    for name in ('policy_version','detector_version','preprocessing_version','band_version'):
                        require(p[name]==a['cfg'][name],'measurement version mismatch')
                    require(p['mode']==a['cfg']['mode'],'authority mode mismatch')
                    a['stage']='EVALUATED';a['measurement']=p['label']
                elif kind=='APPROVAL_PENDING':
                    require(a['stage']=='EVALUATED' and p['candidate_digest']==hashlib.sha256(_bytes(a['candidate'])).hexdigest(),'approval target/order')
                    a['stage']='APPROVAL_PENDING'
                elif kind=='APPROVAL_RESOLVED':
                    require(a['stage']=='APPROVAL_PENDING' and type(p['approved']) is bool,'approval resolution order')
                    if p['approved']:require(p['operator']==a['cfg']['operator'],'approval operator mismatch')
                    a['approval']=p['approved'];a['stage']='APPROVAL_RESOLVED'
                elif kind=='DISPATCH_INTENT':
                    cfg=a['cfg'];args=json.loads(a['candidate']['arguments_json'])
                    require(a['stage'] in ('EVALUATED','APPROVAL_RESOLVED') and not a['intent'],'duplicate/early dispatch')
                    require(cfg['execution_enabled'] is True and 'read_excerpt' in cfg['tools'] and args['document_id'] in cfg['documents'],'dispatch permission missing')
                    require(a['measurement'] in ('ALLOW','REVIEW','DENY'),'unknown measurement dispatched')
                    require(not (cfg['mode']=='CONTROLLED' and a['measurement']=='DENY'),'controlled denial dispatched')
                    needs=cfg['require_approval'] or (cfg['mode']=='CONTROLLED' and a['measurement']=='REVIEW')
                    require(not needs or a['approval'] is True,'approval missing')
                    require(p['arguments']==args and p['candidate_digest']==hashlib.sha256(_bytes(a['candidate'])).hexdigest(),'dispatch argument mismatch')
                    dispatches+=1;require(dispatches<=cfg['max_dispatches'],'dispatch budget exceeded')
                    a['intent']=True;a['stage']='DISPATCH_INTENT'
                elif kind in ('COMPLETED','FAILED','UNKNOWN','REFUSED'):
                    require(a['terminal'] is None,'duplicate terminal outcome')
                    if kind in ('COMPLETED','FAILED'):require(a['intent'],'actual result without intent')
                    if kind=='REFUSED':require(not a['intent'],'refusal hides execution')
                    a['terminal']=kind;a['stage']=kind
                elif kind=='POST_CHECK':
                    require(a['terminal'] in ('COMPLETED','FAILED','UNKNOWN'),'postcheck without actual outcome')
                    require(p['disposition'] in ('ALLOW','DENY','ERROR'),'postcheck disposition')
                    require(a['stage']!='POST_CHECK','duplicate postcheck')
                    a['stage']='POST_CHECK'
                else:raise ValueError('unsupported event kind')
        require(current is not None,'missing configuration')
        unknown=[aid for aid,a in actions.items() if a['terminal']=='UNKNOWN' or (a['intent'] and a['terminal'] is None)]
        for aid,a in actions.items():
            if a['terminal'] is None:recorded_gaps.append(aid+': missing terminal evidence')
            if a['intent'] and a['stage']!='POST_CHECK':recorded_gaps.append(aid+': post-check unknown')
        gaps=bool(unknown or recorded_gaps)
        report.update(structure='VALID',coverage='GAPS' if gaps else 'COMPLETE_FOR_DECLARED_PROFILE',
                      unknown_outcomes=unknown,coverage_gaps=recorded_gaps,identity_assurance='local-operator-asserted')
        review=bundle['review']
        if review:
            require(review['target_runtime_sha256']==bundle['runtime_sha256'],'wrong reviewed segment')
            require(review['operator']==current['operator'] and review['actor_kind']=='human'
                    and review['identity_assurance']=='local-operator-asserted'
                    and review['decision'] in ('ACCEPT','HOLD','REJECT') and review['reason'].strip(),'invalid asserted review')
            report['human_review']=review['decision']
    except (ValueError,TypeError,KeyError,AttributeError,IndexError,UnicodeDecodeError,OverflowError,RecursionError) as e:
        report['structure']='INVALID';report['coverage']='UNKNOWN'
        report['errors'].append(e.args[0] if type(e) is _Refused else MALFORMED)
    return report


def check_record(path,*,pins=witness.PINS):
    """(report, witness state) of the receipt file at path and the witness.json beside it. OSError when unreadable."""
    with Path(path).open('rb') as stream:raw=stream.read(MAX_BYTES+1)
    row=witness.load(Path(path).with_name(witness.WITNESS),witness.MAX_ROW_BYTES)
    state=witness.check(raw,row,pins=pins)
    report=check_receipt(raw)
    del report['witness_reason']  # check_receipt's statement for bytes alone; this record's own state replaces it
    report.update(witness.fields(state))
    saved=witness.load(Path(path).with_name(witness.READING),witness.MAX_READING_BYTES)
    report['reading']={'state':witness.reading_state(raw,row,saved,pins=pins)}  # the saved reading beside the receipt
    return report,state


def explain(raw,state=witness.NOT_REQUESTED):
    """The plain reading of receipt bytes, ending with the sentence of their witness state."""
    report=check_receipt(raw)
    text=f"Structure {report['structure']}; coverage {report['coverage']}; human review {report['human_review']}."
    if report['structure']!='VALID':return text+' Evidence is not usable as a complete record.\n'+witness.sentence(state)
    segment=json.loads(raw)['runtime']
    by_action={}
    for e in segment['events']:
        if e['action_id'] is None:continue
        a=by_action.setdefault(e['action_id'],{'measurement':'unavailable','outcome':'UNKNOWN','approval':'not recorded','post':'not recorded'})
        if e['kind']=='EVALUATED':a['measurement']=e['payload']['label']
        elif e['kind']=='APPROVAL_RESOLVED':a['approval']='asserted human approval' if e['payload']['approved'] else 'unresolved'
        elif e['kind'] in ('COMPLETED','FAILED','UNKNOWN','REFUSED'):a['outcome']=e['kind']
        elif e['kind']=='POST_CHECK':a['post']=e['payload']['disposition']
    for aid,a in by_action.items():
        text+=f"\n{aid}: measured {a['measurement']}; approval {a['approval']}; actual {a['outcome']}; post-check {a['post']}."
    return text+'\nLocal identity is asserted. This explanation grants no authority.\n'+witness.sentence(state)


if __name__=='__main__':
    require=sys.argv[1:2]==[REQUIRE_WITNESSED]
    paths=sys.argv[2:] if require else sys.argv[1:]
    state=witness.NOT_REQUESTED
    unread=dict({'structure':'INVALID','coverage':'UNKNOWN'},**witness.fields(state))
    if len(paths)!=1:result=dict(unread,errors=['usage'])
    else:
        try:result,state=check_record(paths[0])
        except OSError:result=dict(unread,errors=['receipt unreadable'])
    print(json.dumps(result,sort_keys=True))
    print(witness.sentence(state),file=sys.stderr)
    if result['structure']!='VALID':sys.exit(2)
    sys.exit(1 if require and state['reason'] is not None else 0)
