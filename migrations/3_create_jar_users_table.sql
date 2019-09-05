CREATE TABLE jar_users (
  id                SERIAL PRIMARY KEY NOT NULL,
  jar_id            INT NOT NULL,
  user_id           INT NOT NULL,
  created_at        TIMESTAMP NOT NULL DEFAULT now(),
  FOREIGN KEY (jar_id) REFERENCES jars(id),
  FOREIGN KEY (user_id) REFERENCES users(id)
);