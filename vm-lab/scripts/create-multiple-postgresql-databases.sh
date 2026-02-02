#!/bin/bash

set -e
set -u

function create_user_and_database() {
    local database=$1
    local password=$2
    echo "  Creating user and database '$database'"
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
        CREATE USER $database WITH PASSWORD '$password';
        CREATE DATABASE $database;
        GRANT ALL PRIVILEGES ON DATABASE $database TO $database;
EOSQL
}

if [ -n "$POSTGRES_MULTIPLE_DATABASES" ]; then
    echo "Multiple database creation requested: $POSTGRES_MULTIPLE_DATABASES"

    # Create lti database with LTI_DB_PASS
    if [[ "$POSTGRES_MULTIPLE_DATABASES" == *"lti"* ]]; then
        create_user_and_database "lti" "${LTI_DB_PASS:-lti}"
    fi

    # Create lab database with LAB_DB_PASS
    if [[ "$POSTGRES_MULTIPLE_DATABASES" == *"lab"* ]]; then
        create_user_and_database "lab" "${LAB_DB_PASS:-lab}"
    fi

    echo "Multiple databases created"
fi
