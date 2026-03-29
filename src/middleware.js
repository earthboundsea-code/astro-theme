import { clerkMiddleware, createRouteMatcher } from '@clerk/astro/server';

// กำหนดว่าหน้าไหนบ้างที่ต้องล็อกอินก่อน (Public Routes)
const isPublicRoute = createRouteMatcher(['/login(.*)', '/(.*)']); // ให้หน้าแรกเป็นสาธารณะ

export const onRequest = clerkMiddleware((auth, context) => {
  // ถ้าไม่ใช่หน้าสาธารณะ และยังไม่ได้ล็อกอิน ให้เด้งไปหน้า login
  if (!isPublicRoute(context.request) && !auth().userId) {
    return auth().redirectToSignIn();
  }
});