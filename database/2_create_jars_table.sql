CREATE TABLE jars (
  id                SERIAL PRIMARY KEY NOT NULL,
  name              VARCHAR(64) NOT NULL,
  amount            NUMERIC NOT NULL DEFAULT 0,
  admin             INT NOT NULL,
  created_at        TIMESTAMP NOT NULL DEFAULT now(),
  updated_at        TIMESTAMP NOT NULL DEFAULT now(),
  FOREIGN KEY (admin) REFERENCES users(id)
);