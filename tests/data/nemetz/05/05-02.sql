PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE 'users' (
    'name' TEXT,
    'surname' TEXT,
    'lastUpdate' TEXT
);

CREATE TRIGGER log_update_timestamp AFTER UPDATE OF surname ON users BEGIN 
UPDATE users SET lastUpdate = strftime('%Y-%m-%d %H:%M:%S', 'now') 
WHERE rowid = NEW.rowid; END;


INSERT INTO 'users' 
    (name, surname, lastUpdate)
    VALUES
    ('Tilo', 'Engel', NULL),
    ('Hubert', 'Seidel', NULL),
    ('Simon', 'Richter', NULL),
    ('Jonas', 'Zimmermann', NULL);

UPDATE users set surname = "Neumann-Richter" where name = "Simon" AND surname = "Richter";
