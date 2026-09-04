INSERT INTO platform.organizations(id,name,slug,status) VALUES ('00000000-0000-0000-0000-000000000001','Development','development','active') ON CONFLICT DO NOTHING;
INSERT INTO platform.tenants(id,organization_id,name,region,status) VALUES ('00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000001','Root','local','active') ON CONFLICT DO NOTHING;
