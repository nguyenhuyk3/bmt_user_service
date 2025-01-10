CREATE TYPE "roles" AS ENUM (
  'customer',
  'employee',
  'manage',
  'ceo'
);

CREATE TYPE "sex" AS ENUM (
  'female',
  'male'
);

CREATE TABLE "accounts" (
  "email" varchar(64) PRIMARY KEY NOT NULL,
  "password" varchar(64) NOT NULL,
  "role" roles
);

CREATE TABLE "user_infos" (
  "account_email" varchar(64),
  "name" varchar(64) NOT NULL,
  "sex" sex,
  "birth_day" char(16) NOT NULL
);

CREATE TABLE "user_actions" (
  "account_email" varchar(64),
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now()),
  "login_at" timestamptz NOT NULL DEFAULT null,
  "logout_at" timestamptz NOT NULL DEFAULT null
);

CREATE INDEX ON "accounts" ("email");

CREATE INDEX ON "user_infos" ("account_email");

CREATE INDEX ON "user_actions" ("account_email");

ALTER TABLE "user_infos" ADD FOREIGN KEY ("account_email") REFERENCES "accounts" ("email");

ALTER TABLE "user_actions" ADD FOREIGN KEY ("account_email") REFERENCES "accounts" ("email");
