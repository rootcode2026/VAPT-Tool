from app.api.routes.assets import router as assets_router
from app.schemas.asset import AssetDetailResponse, AssetNeighborResponse, AssetResponse
from app.schemas.finding import FindingResponse
from tests.test_persistence import Asset, AssetRelationship, Finding, _session


def test_assets_routes_are_registered():
    assert assets_router.prefix == "/api/v1/assets"
    paths = {getattr(route, "path", "") for route in assets_router.routes}

    assert "/api/v1/assets" in paths
    assert "/api/v1/assets/{asset_id}" in paths


def test_asset_list_filters_by_project_type_and_search():
    db = _session()
    ids = db.info["ids"]

    db.add(
        Asset(
            id="asset-domain",
            project_id=ids["project_id"],
            asset_type="domain",
            value="internal.test",
            extra_data={"sources": ["dns"]},
        )
    )
    db.add(
        Asset(
            id="asset-ip",
            project_id=ids["project_id"],
            asset_type="ip",
            value="10.0.0.8",
            extra_data={"sources": ["nmap"]},
        )
    )
    db.commit()

    lookup = "internal"
    results = (
        db.query(Asset)
        .filter(Asset.project_id == ids["project_id"])
        .filter(Asset.asset_type == "domain")
        .filter(Asset.value.ilike(f"%{lookup}%"))
        .all()
    )

    assert [item.value for item in results] == ["internal.test"]
    payload = AssetResponse.model_validate(results[0]).model_dump()
    assert payload["metadata"]["sources"] == ["dns"]
    assert "extra_data" not in payload
    db.close()


def test_asset_detail_includes_relationships_and_findings():
    db = _session()
    ids = db.info["ids"]

    domain = Asset(
        id="asset-domain",
        project_id=ids["project_id"],
        asset_type="domain",
        value="internal.test",
        extra_data={"sources": ["dns"]},
    )
    child = Asset(
        id="asset-sub",
        project_id=ids["project_id"],
        asset_type="subdomain",
        value="api.internal.test",
        extra_data={"sources": ["subdomain"]},
    )
    db.add_all(
        [
            domain,
            child,
            AssetRelationship(
                id="rel-1",
                project_id=ids["project_id"],
                source_asset_id="asset-domain",
                target_asset_id="asset-sub",
                relationship_type="contains",
                extra_data={
                    "sources": ["subdomain"],
                    "confidence": "medium",
                    "evidence": {"observed_value": "api.internal.test"},
                },
            ),
            Finding(
                id="finding-1",
                scan_id=ids["scan_id"],
                target_id=ids["target_id"],
                asset_id="asset-domain",
                scanner="nuclei",
                title="nginx detected",
                severity="info",
                extra_data={"matched_at": "https://internal.test"},
            ),
        ]
    )
    db.commit()

    related = db.get(Asset, "asset-sub")
    finding = db.get(Finding, "finding-1")
    payload = AssetDetailResponse.model_validate(domain).model_copy(
        update={
            "relationships": [
                AssetNeighborResponse(
                    direction="outgoing",
                    relationship_type="contains",
                    relationship_id="rel-1",
                    asset=AssetResponse.model_validate(related),
                    metadata={
                        "sources": ["subdomain"],
                        "confidence": "medium",
                        "evidence": {"observed_value": "api.internal.test"},
                    },
                    source_asset_id="asset-domain",
                    target_asset_id="asset-sub",
                    source_asset=AssetResponse.model_validate(domain),
                    target_asset=AssetResponse.model_validate(related),
                    created_at=db.get(AssetRelationship, "rel-1").created_at,
                    updated_at=db.get(AssetRelationship, "rel-1").updated_at,
                )
            ],
            "findings": [FindingResponse.model_validate(finding).model_dump()],
        }
    ).model_dump()

    assert payload["value"] == "internal.test"
    assert payload["relationships"][0]["relationship_type"] == "contains"
    assert payload["relationships"][0]["asset"]["value"] == "api.internal.test"
    assert payload["relationships"][0]["source_asset_id"] == "asset-domain"
    assert payload["relationships"][0]["target_asset_id"] == "asset-sub"
    assert payload["relationships"][0]["source_asset"]["value"] == "internal.test"
    assert payload["relationships"][0]["target_asset"]["value"] == "api.internal.test"
    assert payload["relationships"][0]["metadata"]["sources"] == ["subdomain"]
    assert payload["relationships"][0]["created_at"] is not None
    assert payload["relationships"][0]["updated_at"] is not None
    assert payload["findings"][0]["title"] == "nginx detected"
    db.close()
