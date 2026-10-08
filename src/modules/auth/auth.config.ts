function required(name: string) : string {
    const value = process.env[name]?.trim();

    if(!value) {
        throw new Error(`Missing environment variable: ${name}`);
    }

    return value;
}

function validateUrl(name: string) : string {
    const value = required(name);
    const url = new URL(value);

    const localDevelopement = 
        process.env.NODE_ENV === "development" &&
        ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);

    if (
        url.protocol !== "https:" &&
        !(localDevelopement && url.protocol === "http:")
    ) {
        throw new Error(`${name} must use HTTPs outside local developement`);
    }

    if(url.username || url.password || url.search || url.hash) {
        throw new Error(`${name} must not contain credentials, query, or fragment`);
    }

    return value;
}

export const authConfig = {
    issuer : validateUrl("OIDC_ISSUER"),
    jwksUrl: validateUrl("OIDC_JWKS_URL"),
    audience: required("OIDC_AUDIENCE"),
    client_id: required("OIDC_CLIENT_ID"),
    clientSecret: required("OIDC_CLIENT_SECRET"),
    redirectUri: validateUrl("OIDC_REDIRECT_URI"),
};