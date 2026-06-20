PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-16le";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE 'UTF-16𝄞𝕥𠂊𤽜End' (
	'id' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'zip' INT UNSIGNED NULL
);

INSERT INTO 'UTF-16𝄞𝕥𠂊𤽜End' 
	(id, name, surname, zip)
	VALUES
	(20001, 'Theo𝄞𝕥', 'Lorenz', '65428'),
	(20002, 'Andreas', 'Berger', '73469'),
	(20003, 'Margarethe', 'Sauer', '55252'),
	(20004, 'Lennart', 'Winter', '73650'),
	(20005, 'Ida', 'Schmidt', '55150'),
	(20006, 'Michaela', 'Friedrich', '25779'),
	(20007, 'Jörg', 'Lehmann', '90469'),
	(20008, 'Ida', 'Krause', '31655'),
	(20009, 'Mathilda', 'Günther', '72517'),
	(20010, 'Erich', 'Busch', '66504');
