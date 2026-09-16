import {expect,test} from '@playwright/test'

test('real API passive import, persistent Web Surface, Candidate and report',async({page})=>{
  await page.goto('/')
  await page.getByRole('button',{name:'+ New Project'}).click()
  await page.getByLabel('Name').fill('Phase 15.2 browser proof')
  const started=page.waitForResponse(response=>response.url().endsWith('/start')&&response.status()===201)
  await page.getByRole('button',{name:'Configure & start'}).click()
  const session=await (await started).json() as {id:string}
  await expect(page.getByRole('heading',{name:'Session Overview'})).toBeVisible()

  await page.getByRole('button',{name:'Web Surface'}).click()
  await expect(page.getByRole('heading',{name:'Web Surface'})).toBeVisible()
  await expect(page.getByText(/Maximum file size:/)).toBeVisible()
  await page.getByLabel('Burp XML file').setInputFiles('../tests/fixtures/web/phase15-burp.xml')
  await page.getByRole('button',{name:'Import Burp Traffic'}).click()
  await expect(page.getByRole('heading',{name:'Import result'})).toBeVisible({timeout:15_000})
  await expect(page.getByText('/search',{exact:true}).first()).toBeVisible()
  await expect(page.getByText('/login',{exact:true}).first()).toBeVisible()
  await expect(page.getByRole('button',{name:'POST'})).toBeVisible()
  await expect(page.getByText('q',{exact:true})).toBeVisible()
  await expect(page.getByText('password',{exact:true}).first()).toBeVisible()

  const candidate=JSON.stringify({
    'template-id':'passive-header-check',
    info:{name:'<script>alert(1)</script>',severity:'medium'},
    'matcher-name':'headers',
    'matched-at':'http://127.0.0.1:8001/admin',
    type:'http',
    timestamp:'2026-08-25T10:01:00Z',
    'unknown-secret':'PHASE15_LIVE_SECRET',
  })
  const candidateResponse=await page.request.post(`/api/sessions/${session.id}/web/import-template`,{
    data:candidate,
    headers:{'content-type':'application/x-ndjson'},
  })
  expect(candidateResponse.status()).toBe(201)
  expect((await candidateResponse.json()).finding_count).toBe(0)
  await page.getByRole('button',{name:'Rebuild surface'}).click()
  await expect(page.getByText('passive-header-check',{exact:true})).toBeVisible({timeout:15_000})
  await expect(page.getByText('TOOL_REPORTED',{exact:true})).toBeVisible()
  await expect(page.getByText('Candidate',{exact:true})).toBeVisible()
  await expect(page.getByText('Vulnerability',{exact:true})).toHaveCount(0)
  await expect(page.locator('td script')).toHaveCount(0)

  const adminRow=page.getByRole('row').filter({hasText:'/admin'}).first()
  await adminRow.getByRole('button',{name:'GET'}).click()
  await expect(page.getByRole('heading',{name:'Resource detail'})).toBeVisible()
  await expect(page.getByText('TRAFFIC',{exact:true}).first()).toBeVisible()
  await expect(page.getByText('HTML_LINK',{exact:true}).first()).toBeVisible()

  await page.getByRole('button',{name:'Reports'}).click()
  await page.getByRole('button',{name:'Generate evidence-backed report'}).click()
  await expect(page.getByText('COMPLETED',{exact:true}).first()).toBeVisible({timeout:15_000})
})
