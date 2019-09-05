CREATE TABLE users (
  id                SERIAL PRIMARY KEY NOT NULL,
  email             VARCHAR(64) UNIQUE NOT NULL,
  name              VARCHAR(64) NOT NULL,
  password          VARCHAR(128) NOT NULL,
  salt              VARCHAR(32) NULL,
  refresh_token     VARCHAR(128) NULL,
  created_at        TIMESTAMP NOT NULL DEFAULT now(),
  updated_at        TIMESTAMP NOT NULL DEFAULT now()
);