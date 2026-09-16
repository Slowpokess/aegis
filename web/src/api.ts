export type Json = Record<string, unknown>
export type Project = Json & {id:string;name:string;status:string;approval_mode:string;controller_mode:string}
export type Session = Json & {id:string;name:string;status:string}
export type Tool = Json & {tool_id:string;display_name:string;version:string|null;available:boolean;enabled:boolean;category:string;capabilities:string[];profiles:{id:string;description:string;capability:string;risk:string}[];risk_class:string;execution_backend:string}

const base = import.meta.env.VITE_AEGIS_API ?? '/api'
async function request<T>(path:string, init?:RequestInit):Promise<T>{
  const response=await fetch(`${base}${path}`,{...init,headers:{'Content-Type':'application/json',...(init?.headers??{})}})
  if(!response.ok){const body=await response.json().catch(()=>({detail:response.statusText})) as {detail?:unknown};const detail=typeof body.detail==='string'?body.detail:JSON.stringify(body.detail);throw new Error(detail||`HTTP ${response.status}`)}
  return response.json() as Promise<T>
}
export const api={
  projects:()=>request<Project[]>('/projects'),
  createProject:(data:Json)=>request<Project>('/projects',{method:'POST',body:JSON.stringify(data)}),
  configureProject:(id:string,data:Json)=>request<Project>(`/projects/${id}`,{method:'PUT',body:JSON.stringify(data)}),
  startProject:(id:string)=>request<Session>(`/projects/${id}/start`,{method:'POST'}),
  sessions:(id:string)=>request<Session[]>(`/projects/${id}/sessions`),
  overview:(id:string)=>request<Json>(`/sessions/${id}/status`),
  events:(id:string)=>request<Json[]>(`/sessions/${id}/events?limit=200`),
  actions:(id:string)=>request<Json[]>(`/sessions/${id}/actions?limit=200`),
  gaps:(id:string)=>request<Json[]>(`/sessions/${id}/gaps`),
  findings:(id:string)=>request<Json[]>(`/sessions/${id}/findings`),
  model:(id:string)=>request<Json>(`/sessions/${id}/model`),
  graph:(id:string)=>request<Json>(`/sessions/${id}/graph`),
  reports:(id:string)=>request<Json[]>(`/sessions/${id}/reports`),
  webSurface:(id:string)=>request<Json>(`/sessions/${id}/web-surface`),
  webResources:(id:string)=>request<Json[]>(`/sessions/${id}/web-resources`),
  webParameters:(id:string)=>request<Json[]>(`/sessions/${id}/web-parameters`),
  webTemplates:(id:string)=>request<Json[]>(`/sessions/${id}/http-request-templates`),
  webCandidates:(id:string)=>request<Json[]>(`/sessions/${id}/web-template-candidates`),
  webAssessmentRuns:(id:string)=>request<Json[]>(`/sessions/${id}/web/assessment-runs`),
  previewWebDiscovery:(id:string,resource_id:string,profile:string)=>request<Json>(`/sessions/${id}/web/discover`,{method:'POST',body:JSON.stringify({resource_id,profile,execute:false})}),
  runWebDiscovery:(id:string,resource_id:string,profile:string)=>request<Json>(`/sessions/${id}/web/discover`,{method:'POST',body:JSON.stringify({resource_id,profile,execute:true})}),
  previewWebAssessment:(id:string,resource_ids:string[],profile:string)=>request<Json>(`/sessions/${id}/web/assess`,{method:'POST',body:JSON.stringify({resource_ids,profile,execute:false})}),
  runWebAssessment:(id:string,resource_ids:string[],profile:string)=>request<Json>(`/sessions/${id}/web/assess`,{method:'POST',body:JSON.stringify({resource_ids,profile,execute:true})}),
  webResource:(id:string)=>request<Json>(`/web-resources/${id}`),
  buildWebSurface:(id:string)=>request<Json>(`/sessions/${id}/web/build`,{method:'POST'}),
  importBurp:async(id:string,file:File):Promise<Json>=>{
    const response=await fetch(`${base}/sessions/${id}/web/import-burp`,{method:'POST',headers:{'Content-Type':'application/xml'},body:file})
    if(!response.ok){const body=await response.json().catch(()=>({detail:response.statusText})) as {detail?:unknown};throw new Error(typeof body.detail==='string'?body.detail:JSON.stringify(body.detail))}
    return response.json() as Promise<Json>
  },
  generateReport:(id:string)=>request<Json>(`/sessions/${id}/reports`,{method:'POST'}),
  tools:()=>request<Tool[]>('/tools'),
  runtime:()=>request<Json>('/runtime'),
  control:(id:string,verb:'pause'|'resume'|'stop')=>request<Json>(`/sessions/${id}/${verb}`,{method:'POST'}),
  step:(id:string)=>request<Json>(`/sessions/${id}/controller/step`,{method:'POST'}),
  approve:(id:string)=>request<Json>(`/actions/${id}/approve`,{method:'POST',body:'{}'}),
  reject:(id:string)=>request<Json>(`/actions/${id}/reject`,{method:'POST',body:'{}'})
}
