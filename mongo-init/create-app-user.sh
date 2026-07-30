#!/bin/bash
# docker-entrypoint-initdb.d convention: the official mongo image sources
# every *.sh file here (only on the container's very FIRST start with an
# empty data volume - see docker-compose.yml's comment on this). At this
# point mongod is up on 127.0.0.1:27017 with auth temporarily disabled
# (the standard entrypoint's own bootstrap already created the root user
# from MONGO_INITDB_ROOT_USERNAME/PASSWORD the same way, without needing
# to authenticate first) - no root credentials needed here either.
#
# Creates a SEPARATE, least-privilege user: readWrite on just the
# "honeypot" database, not root - what every app service should actually
# connect as (MONGO_USERNAME/MONGO_PASSWORD in docker-compose.yml), so a
# compromised app container can't touch other databases or run admin
# commands. The root user from MONGO_INITDB_ROOT_USERNAME/PASSWORD still
# exists for genuine admin work (backups, `mongosh` troubleshooting).
set -e

app_username="$(cat "$MONGO_APP_USERNAME_FILE")"
app_password="$(cat "$MONGO_APP_PASSWORD_FILE")"
app_database="${MONGO_INITDB_DATABASE:-honeypot}"

# jq --arg safely JSON/JS-string-escapes arbitrary content (quotes,
# backslashes, ...) - same technique the entrypoint's own _js_escape()
# uses above in this same script for the root user, rather than
# interpolating raw values into a JS literal.
js_username="$(jq --null-input --arg str "$app_username" '$str')"
js_password="$(jq --null-input --arg str "$app_password" '$str')"
js_database="$(jq --null-input --arg str "$app_database" '$str')"

echo "create-app-user.sh: creating least-privilege app user on database '$app_database'"

mongosh --host 127.0.0.1 --port 27017 --quiet "$app_database" <<-EOJS
	db.createUser({
		user: ${js_username},
		pwd: ${js_password},
		roles: [ { role: 'readWrite', db: ${js_database} } ]
	})
EOJS
