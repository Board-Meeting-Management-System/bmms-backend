export interface CreateOrganizationBody {
  name: string;
  slug: string;
  secretaryEmail: string;
}

export interface CreateOrganizationHeaders {
  "idempotency-key": string;
}

export const createOrganizationSchema = {
  body: {
    type: "object",
    additionalProperties: false,
    required: ["name", "slug", "secretaryEmail"],

    properties: {
      name: {
        type: "string",
        minLength: 2,
        maxLength: 150,
        pattern: "\\S",
      },

      slug: {
        type: "string",
        minLength: 3,
        maxLength: 63,
        pattern: "^[a-z0-9]+(?:-[a-z0-9]+)*$",
      },

      secretaryEmail: {
        type: "string",
        format: "email",
        maxLength: 254,
      },
    },
  },

  headers: {
    type: "object",
    required: ["idempotency-key"],

    properties: {
      "idempotency-key": {
        type: "string",
        format: "uuid",
      },
    },
  },

  response: {
    202: {
      type: "object",
      additionalProperties: false,
      required: ["tenantId", "jobId", "status"],

      properties: {
        tenantId: {
          type: "string",
          format: "uuid",
        },

        jobId: {
          type: "string",
          format: "uuid",
        },

        status: {
          type: "string",
          enum: ["provisioning"],
        },
      },
    },
  },
} as const;


/*
{
  "name": "ABC Company",
  "slug": "abc-company",
  "secretaryEmail": "secretary@example.com"
}
*/