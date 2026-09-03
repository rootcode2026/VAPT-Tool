"use client";

import { AuthProvider } from "@/lib/auth/AuthProvider";

export default function Providers({ children }) {
  return <AuthProvider>{children}</AuthProvider>;
}
