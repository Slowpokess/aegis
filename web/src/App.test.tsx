import {cleanup,fireEvent,render,screen,waitFor} from '@testing-library/react'
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest'
import {App} from './App'

const response=(value:unknown)=>Promise.resolve({ok:true,json:()=>Promise.resolve(value)})
describe('Operator console',()=>{beforeEach(()=>{vi.stubGlobal('fetch',vi.fn((url:string)=>{if(url.endsWith('/projects'))return response([]);if(url.endsWith('/tools'))return response([{tool_id:'demo_tool',display_name:'Demo <script>alert(1)</script>',version:'v1',available:true,enabled:false,category:'VALIDATION',capabilities:['HTTP_REQUEST'],profiles:[],risk_class:'PASSIVE',execution_backend:'PYTHON_NATIVE',ui:{summary:'fixture'}}]);if(url.endsWith('/runtime'))return response({version:'0.14.0'});return response([])}))});afterEach(()=>cleanup())
it('creates a project form without executing target operations',async()=>{render(<App/>);expect(screen.getByRole('heading',{name:'New project'})).toBeInTheDocument();expect(screen.getByRole('button',{name:'Configure & start'})).toBeInTheDocument()})
it('renders registry tools generically and escapes target-controlled markup',async()=>{render(<App/>);screen.getByRole('button',{name:'Tools'}).click();await waitFor(()=>expect(screen.getByText('Demo <script>alert(1)</script>')).toBeInTheDocument());expect(document.querySelector('script[src="alert(1)"]')).toBeNull()})})

it('shows persisted Web Surface candidates as escaped Candidates, never vulnerabilities',async()=>{
  vi.stubGlobal('fetch',vi.fn((url:string)=>{
    if(url.endsWith('/projects'))return response([{id:'p1',name:'P1',status:'RUNNING',approval_mode:'AUTO',controller_mode:'AUTO'}])
    if(url.endsWith('/projects/p1/sessions'))return response([{id:'s1',name:'S1',status:'RUNNING'}])
    if(url.endsWith('/tools'))return response([])
    if(url.endsWith('/runtime'))return response({web_import_max_bytes:10_000_000})
    if(url.endsWith('/sessions/s1/status'))return response({scope:{hosts:['127.0.0.1']},counts:{}})
    if(url.endsWith('/sessions/s1/web-surface'))return response({counts:{resources:1,parameters:0,forms:0,template_candidates:1,sources:1},methods:{GET:1},snapshot:{web_surface_sha256:'a'.repeat(64)}})
    if(url.endsWith('/sessions/s1/web-resources'))return response([{id:'r1',method:'GET',path:'/<script>alert(1)</script>',resource_type:'PAGE',source_count:1,parameter_count:0,candidate_count:1,finding_count:0}])
    if(url.endsWith('/sessions/s1/web-template-candidates'))return response([{id:'c1',template_id:'xss-label',template_name:'<script>alert(1)</script>',classification:'TOOL_REPORTED',finding_created:false}])
    if(url.includes('/sessions/s1/'))return response([])
    return response({})
  }))
  render(<App/>)
  await waitFor(()=>expect(screen.getByRole('option',{name:'P1'})).toBeInTheDocument())
  fireEvent.change(screen.getByLabelText('Project'),{target:{value:'p1'}})
  await waitFor(()=>expect(screen.getByRole('button',{name:'Web Surface'})).toBeInTheDocument())
  screen.getByRole('button',{name:'Web Surface'}).click()
  await waitFor(()=>expect(screen.getByText('<script>alert(1)</script>')).toBeInTheDocument())
  expect(screen.getByText('Candidate')).toBeInTheDocument()
  expect(screen.queryByText('Vulnerability')).not.toBeInTheDocument()
  expect(document.querySelector('td script')).toBeNull()
})

it('loads active assessment lifecycle and never sends client approval authority',async()=>{
  cleanup()
  const fetchMock=vi.fn((url:string,init?:RequestInit)=>{
    if(url.endsWith('/projects'))return response([{id:'p1',name:'P1',status:'RUNNING',approval_mode:'APPROVE_EVERY_ACTION',controller_mode:'SAFE'}])
    if(url.endsWith('/projects/p1/sessions'))return response([{id:'s1',name:'S1',status:'RUNNING'}])
    if(url.endsWith('/tools'))return response([])
    if(url.endsWith('/runtime'))return response({web_import_max_bytes:10_000_000})
    if(url.endsWith('/sessions/s1/status'))return response({scope:{hosts:['127.0.0.1']},counts:{}})
    if(url.endsWith('/sessions/s1/web-surface'))return response({counts:{resources:1},methods:{GET:1},snapshot:{}})
    if(url.endsWith('/sessions/s1/web-resources'))return response([{id:'r1',method:'GET',path:'/admin',resource_type:'PAGE'}])
    if(url.endsWith('/sessions/s1/web/assessment-runs'))return response([{action_id:'a1',tool_id:'ffuf',profile:'web_content_small',status:'WAITING_FOR_APPROVAL',approval_status:'PENDING',tool_run_id:null}])
    if(url.endsWith('/sessions/s1/web/discover')&&init?.method==='POST'){
      const body=JSON.parse(String(init.body)) as Record<string,unknown>
      return response(body.execute===false?{policy_allowed:true,policy_reason:'ALLOWED',approval_required:true,estimated_requests:4,timeout_seconds:20,max_concurrency:2,capability:'WEB_CONTENT_DISCOVERY'}:{action_id:'a1',status:'WAITING_FOR_APPROVAL',approval_status:'PENDING',tool_run_id:null})
    }
    if(url.includes('/sessions/s1/'))return response([])
    return response({})
  })
  vi.stubGlobal('fetch',fetchMock)
  render(<App/>)
  await waitFor(()=>expect(screen.getByRole('option',{name:'P1'})).toBeInTheDocument())
  fireEvent.change(screen.getByLabelText('Project'),{target:{value:'p1'}})
  screen.getByRole('button',{name:'Web Surface'}).click()
  await waitFor(()=>expect(screen.getByText('WAITING_FOR_APPROVAL')).toBeInTheDocument())
  screen.getByRole('button',{name:'Preview policy & budget'}).click()
  await waitFor(()=>expect(screen.getByText('REQUIRED')).toBeInTheDocument())
  screen.getByRole('button',{name:'Request active assessment'}).click()
  await waitFor(()=>expect(screen.getByText(/Action a1/)).toBeInTheDocument())
  const execution=fetchMock.mock.calls.find(([url,init])=>url.endsWith('/web/discover')&&JSON.parse(String(init?.body)).execute===true)
  expect(execution).toBeDefined()
  expect(String(execution?.[1]?.body)).not.toContain('operator_approved')
})
