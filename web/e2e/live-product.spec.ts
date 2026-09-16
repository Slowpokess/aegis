import {expect,test} from '@playwright/test'

test('real API project, controller and approval workflow',async({page})=>{
  await page.goto('/')
  await page.getByRole('button',{name:'+ New Project'}).click()
  await page.getByLabel('Name').fill('Phase 14 browser proof')
  await page.getByLabel('Approval mode').selectOption('APPROVE_EVERY_ACTION')
  await page.getByRole('button',{name:'Configure & start'}).click()
  await expect(page.getByRole('heading',{name:'Session Overview'})).toBeVisible()
  await expect(page.getByText('APPROVE_EVERY_ACTION')).toBeVisible()
  await page.getByRole('button',{name:'START / STEP'}).click()
  await expect(page.getByText('Approval required',{exact:true})).toBeVisible({timeout:15_000})
  await page.getByRole('button',{name:'APPROVE'}).click()
  await expect(page.getByText('Approval required',{exact:true})).not.toBeVisible({timeout:20_000})
  await page.getByRole('button',{name:'Timeline'}).click()
  await expect(page.getByRole('heading',{name:'Research Timeline'})).toBeVisible()
})
