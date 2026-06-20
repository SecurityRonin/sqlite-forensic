PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE "%" (
	'id' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'zip' INT UNSIGNED NULL
);

INSERT INTO "%" 
	(id, name, surname, zip)
	VALUES
	(20001, 'Erich', 'Braun', '88459'),
	(20002, 'Katja', 'Krause', '9468'),
	(20003, 'Luise', 'Thomas', '26670'),
	(20004, 'Richard', 'Lange', '80538'),
	(20005, 'Luise', 'Möller', '6711'),
	(20006, 'Florian', 'Wagner', '88317'),
	(20007, 'Stefanie', 'Dietrich', '90537'),
	(20008, 'Sabine', 'Braun', '6774'),
	(20009, 'Lara', 'Kraus', '34308'),
	(20010, 'Else', 'Berger', '73579');

