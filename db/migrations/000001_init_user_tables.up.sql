CREATE TYPE "role" AS ENUM (
  'customer',
  'employee',
  'manage',
  'ceo'
);

CREATE TYPE "sex" AS ENUM (
  'female',
  'male'
);

CREATE TABLE "account" (
  "email" varchar(64) PRIMARY KEY NOT NULL,
  "password" varchar(64) NOT NULL,
  "role" role
);

CREATE TABLE "user_info" (
  "account_email" varchar(64),
  "name" varchar(64) NOT NULL,
  "sex" sex,
  "birth_day" char(16) NOT NULL
);

CREATE TABLE "user_action" (
  "account_email" varchar(64),
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now()),
  "login_at" timestamptz NOT NULL DEFAULT null,
  "logout_at" timestamptz NOT NULL DEFAULT null
);

CREATE INDEX ON "account" ("email");

CREATE INDEX ON "user_info" ("account_email");

CREATE INDEX ON "user_action" ("account_email");

ALTER TABLE "user_info" ADD FOREIGN KEY ("account_email") REFERENCES "account" ("email");

ALTER TABLE "user_action" ADD FOREIGN KEY ("account_email") REFERENCES "account" ("email");
