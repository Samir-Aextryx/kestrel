import express from "express";

const router = express.Router();

router.get("/openapi.json", (req, res) => {
  res.json({
    openapi: "3.1.0",
    info: {
      title: "KESTREL autonomous security research API",
      version: "1.0.0",
      description: "Machine-first API. Bearer tokens. Goals are the primary unit; scans are execution records.",
    },
    servers: [{ url: "/api" }],
    components: {
      securitySchemes: {
        bearer: { type: "http", scheme: "bearer" },
      },
    },
    security: [{ bearer: [] }],
    paths: {
      "/goals": {
        post: {
          summary: "Create a goal",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["objective", "target", "targetType"],
                  properties: {
                    objective: { type: "string" },
                    target: { type: "string" },
                    targetType: { type: "string", enum: ["code", "web", "api", "container", "iac", "binary", "mixed"] },
                    projectId: { type: "string" },
                    autonomyLevel: { type: "string", enum: ["observe", "propose", "supervised", "autonomous"] },
                  },
                },
              },
            },
          },
          responses: { "201": { description: "Goal created" } },
        },
        get: { summary: "List goals", responses: { "200": { description: "Goals" } } },
      },
      "/goals/{id}": {
        get: {
          summary: "Read a goal",
          parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
          responses: { "200": { description: "Goal" } },
        },
      },
      "/goals/{id}/approve": {
        post: {
          summary: "Approve and start a goal",
          parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
          responses: { "200": { description: "Started" } },
        },
      },
      "/scans/{id}": {
        get: {
          summary: "Read a scan",
          parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
          responses: { "200": { description: "Scan" } },
        },
      },
      "/scans/{id}/findings": {
        get: {
          summary: "List findings",
          parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
          responses: { "200": { description: "Findings" } },
        },
      },
      "/scans/{id}/reports": {
        post: {
          summary: "Generate a signed report",
          parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
          responses: { "201": { description: "Report" } },
        },
      },
      "/autonomy/policy": {
        get: { summary: "Read policy", responses: { "200": { description: "Policy" } } },
        put: { summary: "Update policy", responses: { "200": { description: "Policy" } } },
      },
      "/agent/quickstart": {
        post: {
          summary: "Create an agent identity, goal and MCP config in one call",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["objective", "target", "targetType"],
                  properties: {
                    objective: { type: "string" },
                    target: { type: "string" },
                    targetType: { type: "string" },
                    projectId: { type: "string" },
                    autonomyLevel: { type: "string" },
                  },
                },
              },
            },
          },
          responses: { "201": { description: "Agent token, goal and MCP config" } },
        },
      },
      "/research/overview": {
        get: { summary: "Confirmed zero-days across workspaces", responses: { "200": { description: "Research overview" } } },
      },
      "/research": {
        get: {
          summary: "Hypotheses for a scan",
          parameters: [{ name: "scanId", in: "query", required: true, schema: { type: "string" } }],
          responses: { "200": { description: "Research detail" } },
        },
      },
      "/findings/{id}/poc": {
        get: {
          summary: "Read a reproducible PoC bundle",
          parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
          responses: { "200": { description: "PoC bundle and source" } },
        },
      },
      "/health": { get: { summary: "Health", security: [], responses: { "200": { description: "OK" } } } },
    },
  });
});

export default router;
