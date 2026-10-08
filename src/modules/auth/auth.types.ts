export interface VerifiedIdentity {
    issuer: string;
    subject: string;
    email: string | null;
    emailVerified: boolean;
}

export interface AuthUser {
    id: string,
    email: string | null,
    emailVerified: boolean;
    status: "active" | "disabled";
    isPlatformAdmin: boolean;
}

declare module "fastify" {
    interface FastifyRequest {
        authUser: AuthUser | null;
    }
}