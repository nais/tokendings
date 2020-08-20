CREATE TABLE IF NOT EXISTS clients
(
    client_id varchar(100)             NOT NULL,
    data      JSONB                    NOT NULL,
    PRIMARY KEY (client_id),
    created   TIMESTAMP WITH TIME ZONE NOT NULL default (now() at time zone 'utc')
);

CREATE TABLE IF NOT EXISTS token_issuer_keys
(
    kid     varchar(36)              NOT NULL,
    jwk     text                     NOT NULL,
    PRIMARY KEY (kid),
    created TIMESTAMP WITH TIME ZONE NOT NULL default (now() at time zone 'utc')
);

CREATE TABLE IF NOT EXISTS rsakeys
(
    id          BIGINT,
    current_key  varchar(2000)            NOT NULL,
    previous_key varchar(2000)            NOT NULL,
    next_key     varchar(2000)            NOT NULL,
    expiry      TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (id)
);


