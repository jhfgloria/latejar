ALTER TABLE jar_users
ADD CONSTRAINT unique_jar_user UNIQUE (jar_id, user_id);