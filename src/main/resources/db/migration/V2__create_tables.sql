DROP TABLE IF EXISTS token_issuer_keys;

CREATE TABLE IF NOT EXISTS rotatable_keys
(
    id          BIGINT,
    current_key  text            NOT NULL,
    previous_key text            NOT NULL,
    next_key     text            NOT NULL,
    expiry       varchar(50)     NOT NULL,
    PRIMARY KEY (id)
);


