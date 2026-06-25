CREATE TABLE attacks (
        ip TEXT PRIMARY KEY,
        tries INTEGER,
        first_try INTEGER,
        last_try INTEGER,
        estado TEXT
);
