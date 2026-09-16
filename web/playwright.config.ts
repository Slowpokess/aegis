import {defineConfig} from '@playwright/test'
export default defineConfig({testDir:'./e2e',workers:1,use:{baseURL:'http://127.0.0.1:4173'},webServer:{command:'npm run dev',url:'http://127.0.0.1:4173',reuseExistingServer:true}})
