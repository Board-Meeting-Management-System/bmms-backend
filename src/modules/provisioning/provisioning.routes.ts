import type { FastifyInstance } from "fastify";

import { authenticate } from "../auth/authenticate.js";
import { requirePlatformAdmin } from "../auth/require-platform-admin.js";
import { getProvisioningJob, retryFailedJob } from "./provisioning.repository.js";


export async function provisioningRoutes(app: FastifyInstance) {
    app.get<{Params: {id: string}}> (
        "/admin/provisioning-jobs/:id",
        {
            schema:{
                params: {
                    type: "object",
                    additionalProperties: false,
                    required: ["id"],
                    properties : {
                        id: { type: "string", format: "uuid"},
                    },
                },
            },

            preHandler: [authenticate, requirePlatformAdmin],
        },

        async (request, reply) => {
            reply.header("cache-control", "no-store");

            try{
                const job = await getProvisioningJob(request.params.id);

                if(!job) {
                    return reply.code(404).send({
                        error: "JOB_NOT_FOUND",
                        message: "Provisioning job not found."
                    });
                }

                return reply.send({job});
            }catch(error){
                request.log.error({
                    event: "provisioning job read failed",
                    code:
                        error !== null &&
                        typeof error === "object" &&
                        "code" in error &&
                        typeof error.code === "string"
                            ? error.code
                            : undefined
                },
                "Unable to retrive provisioning job",
            );


            return reply.code(503).send({
                error: "PROVISIONING_UNAVAILABLE",
                message: "Unable to retrieve provisioning progress."
            });

            }
        },
    );

    // Authorized retry of a failed job: resumes from the failed step.
    app.post<{ Params: { id: string } }>(
        "/admin/provisioning-jobs/:id/retry",
        {
            schema: {
                params: {
                    type: "object",
                    additionalProperties: false,
                    required: ["id"],
                    properties: { id: { type: "string", format: "uuid" } },
                },
            },
            onRequest: [authenticate, requirePlatformAdmin],
            config: { rateLimit: { max: 10, timeWindow: "1 minute" } },
        },
        async (request, reply) => {
            reply.header("Cache-Control", "no-store");
            const result = await retryFailedJob(request.params.id);
            if (result === "not_found") {
                return reply.code(404).send({ error: "JOB_NOT_FOUND", message: "Provisioning job not found." });
            }
            if (result === "not_failed") {
                return reply.code(409).send({ error: "JOB_NOT_FAILED", message: "Only failed provisioning can be retried." });
            }
            return reply.code(202).send({ job: await getProvisioningJob(request.params.id) });
        },
    );
}
