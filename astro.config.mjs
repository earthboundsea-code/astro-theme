
import { defineConfig } from 'astro/config';
import node from '@astrojs/node'; // 1. นำเข้า Adapter
import clerk from '@clerk/astro';

export default defineConfig({
  output: 'server', // 2. ยืนยันว่าใช้ระบบ Server
  adapter: node({
    mode: 'standalone', // 3. ตั้งค่าให้รันบน Node.js
  }),
  integrations: [
    clerk(), // 4. ระบบ Login
  ],
});