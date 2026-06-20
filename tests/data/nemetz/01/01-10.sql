PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE " " (
	'id' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'zip' INT UNSIGNED NULL
);

INSERT INTO " " 
	(id, name, surname, zip)
	VALUES
	(20001, 'Marlene', 'Roth', '72297'),
	(20002, 'Charlotte', 'Sauer', '82549'),
	(20003, 'Karsten', 'Schneider', '26127'),
	(20004, 'Else', 'Vogt', '25870'),
	(20005, 'Vincent', 'Friedrich', '44869'),
	(20006, 'Dennis', 'Köhler', '45772'),
	(20007, 'Mika', 'Ludwig', '78479'),
	(20008, 'Erich', 'Wolff', '23730'),
	(20009, 'Luise', 'Wagner', '86637'),
	(20010, 'Hanna', 'Haas', '79283');

