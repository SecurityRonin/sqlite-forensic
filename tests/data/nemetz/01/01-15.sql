PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE "," (
	'id' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'zip' INT UNSIGNED NULL
);

INSERT INTO "," 
	(id, name, surname, zip)
	VALUES
	(20001, 'Leni', 'Hartmann', '87751'),
	(20002, 'Kai', 'Voigt', '72505'),
	(20003, 'Silke', 'Berger', '8309'),
	(20004, 'Mia', 'Krüger', '38442'),
	(20005, 'Leni', 'Bergmann', '74736'),
	(20006, 'Mathilda', 'Weber', '83679'),
	(20007, 'Philipp', 'Schulze', '24791'),
	(20008, 'Lennart', 'Klein', '66877'),
	(20009, 'Jan', 'Braun', '47239'),
	(20010, 'Luis', 'Roth', '94436');

