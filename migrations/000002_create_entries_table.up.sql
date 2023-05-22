BEGIN;

CREATE TABLE IF NOT EXISTS entries(
   id UUID NOT NULL,
   user_id UUID NOT NULL REFERENCES users(id),
   metadata BYTEA NOT NULL,
   locked BOOL NOT NULL DEFAULT FALSE,
   locked_until TIMESTAMP NOT NULL DEFAULT now(),
   PRIMARY KEY(id, user_id)
);

COMMIT;
