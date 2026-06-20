PRAGMA page_size=1024;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TEMP TABLE users (name TEXT, surname TEXT);
INSERT INTO users VALUES ("Florian", "Meier");
INSERT INTO users VALUES ("Georg", "Huber");
