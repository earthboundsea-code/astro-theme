import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';
import clerk from '@clerk/astro'; // 👈 1. เพิ่มการนำเข้า Clerk

// https://astro.build/config
export default defineConfig({
  // 👈 2. เปลี่ยนจาก "static" เป็น "server" เพื่อให้ระบบ Login ทำงานได้
  output: "server", 

  // 👈 3. เพิ่มการตั้งค่า Clerk ในส่วน integrations
  integrations: [
    clerk()
  ],

  vite: {
    plugins: [
      tailwindcss()
    ]
  }
});
