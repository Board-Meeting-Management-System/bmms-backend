-- Preserve access for the account running migrations.
-- In your local setup, this is also the API/worker account.
DO $$
BEGIN
    EXECUTE format(
        'GRANT CONNECT ON DATABASE %I TO %I',
        current_database(),
        current_user
    );

    EXECUTE format(
        'REVOKE CONNECT, TEMPORARY ON DATABASE %I FROM PUBLIC',
        current_database()
    );
END
$$;