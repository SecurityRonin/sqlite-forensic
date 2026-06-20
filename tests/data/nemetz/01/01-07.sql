PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE "A'b'c" (
	'id' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'zip' INT UNSIGNED NULL
);

INSERT INTO "A'b'c" 
	(id, name, surname, zip)
	VALUES
	(20001, 'Mia', 'Krüger', '24640'),
	(20002, 'Jörg', 'Sommer', '69434'),
	(20003, 'Claudia', 'Hartmann', '73773'),
	(20004, 'Elisa', 'Schäfer', '96479'),
	(20005, 'Kai', 'Sauer', '8233'),
	(20006, 'Walter', 'Haas', '96317'),
	(20007, 'Markus', 'Walter', '17255'),
	(20008, 'Richard', 'Kraus', '63607'),
	(20009, 'Kurt', 'Graf', '35327'),
	(20010, 'Jörg', 'Bergmann', '1848');

