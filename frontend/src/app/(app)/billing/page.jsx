"use client";
import { useEffect, useState } from "react";
import PageHeader from "@/components/ui/PageHeader";
import LoadingState from "@/components/ui/LoadingState";
import { useProjectContext } from "@/lib/project-context";
import { api } from "@/lib/api/client";

export default function BillingPage(){
  const { selectedProjectId } = useProjectContext();
  const [data,setData]=useState(null);
  const [loading,setLoading]=useState(true);
  useEffect(()=>{
    async function load(){
      try{
        // fetch via org id from project context - use current org via me endpoint not available, placeholder
        const res=await api.get("/api/v1/plans");
        setData(res);
      }catch(e){ setData({error: e.message})}
      finally{ setLoading(false)}
    }
    load();
  },[]);
  if(loading) return <LoadingState message="Loading billing..." />;
  return (
    <div className="space-y-6">
      <PageHeader title="Billing & Plan" description="Current plan, subscription, usage and entitlements" />
      <div className="rounded-md border bg-surface p-4">
        <h3 className="text-sm font-semibold">Current Plan</h3>
        <p className="text-xs text-muted">Usage and limits are enforced server-side. Upgrade requires org_admin.</p>
        <pre className="mt-2 text-xs bg-canvas p-2 rounded overflow-auto">{JSON.stringify(data, null, 2)?.slice(0,1000)}</pre>
      </div>
      <p className="text-xs text-muted">Payment via provider checkout — webhook updates subscription atomically.</p>
    </div>
  );
}
