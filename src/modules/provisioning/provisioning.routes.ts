import type { FastifyInstance } from "fastify";

import { authenticate } from "../auth/authenticate.js";
import { requirePlatformAdmin } from "../auth/require-platform-admin.js";
import { getProvisioningJob } from "./provisioning.repository.js";
import { error } from "console";


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
                        error: "JOB Not found",
                        messaage: "Provisioning not found"
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
                error: "Provisioning Unavailable",
                message: "Unable to retrive provisioning progress"
            });

            }
        },
    );
}