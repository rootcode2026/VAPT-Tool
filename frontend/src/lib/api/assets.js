import { api } from "./client";

export function listAssets(query) {
  return api.get("/api/v1/assets", { query });
}

export function getAsset(assetId) {
  return api.get(`/api/v1/assets/${assetId}`);
}
