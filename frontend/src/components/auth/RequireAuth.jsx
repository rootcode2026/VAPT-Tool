"use client";

import { useEffect } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import LoadingState from "@/components/ui/LoadingState";
import { useAuth } from "@/lib/auth/AuthProvider";

export default function RequireAuth({ children }) {
  const { status } = useAuth();
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  useEffect(() => {
    if (status !== "unauthenticated") {
      return;
    }

    const search = searchParams?.toString();
    const next = `${pathname}${search ? `?${search}` : ""}`;
    const target =
      next && next !== "/login"
        ? `/login?next=${encodeURIComponent(next)}`
        : "/login";

    router.replace(target);
  }, [status, router, pathname, searchParams]);

  if (status === "loading") {
    return <LoadingState message="Loading security data..." />;
  }

  if (status !== "authenticated") {
    return <LoadingState message="Redirecting to sign in..." />;
  }

  return children;
}
