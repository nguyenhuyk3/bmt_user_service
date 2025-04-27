CREATE TYPE "roles" AS ENUM (
  'customer',
  'employee',
  'manager',
  'ceo'
);

CREATE TYPE "sex" AS ENUM (
  'female',
  'male'
);

CREATE TYPE "sources" AS ENUM (
  'app',
  'facebook',
  'google'
);

CREATE TABLE "accounts" (
  "email" varchar(64) PRIMARY KEY NOT NULL,
  "password" varchar(64) NOT NULL,
  "source" sources,
  "role" roles
);

CREATE TABLE "user_infos" (
  "email" varchar(64),
  "name" varchar(64) NOT NULL,
  "sex" sex,
  "birth_day" char(16) NOT NULL
);

CREATE TABLE "user_actions" (
  "email" varchar(64),
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now()),
  "login_at" timestamptz DEFAULT null,
  "logout_at" timestamptz DEFAULT null
);

CREATE INDEX ON "accounts" ("email");

CREATE INDEX ON "user_infos" ("email");

CREATE INDEX ON "user_actions" ("email");

ALTER TABLE "user_infos" ADD FOREIGN KEY ("email") REFERENCES "accounts" ("email");

ALTER TABLE "user_actions" ADD FOREIGN KEY ("email") REFERENCES "accounts" ("email");
