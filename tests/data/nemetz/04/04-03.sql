PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE '自由' (
	'id' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'zip' INT UNSIGNED NULL
);

INSERT INTO '自由' 
	(id, name, surname, zip)
	VALUES
	(20001, 'Friedrich', 'Busch', '9599'),
	(20002, 'Josef', 'Schmidt', '99092'),
	(20003, 'Markus', 'Schulte', '67578'),
	(20004, 'Mathilda', 'Schuster', '29664'),
	(20005, 'Claudia', 'Berger', '74081'),
	(20006, 'Maximilian', 'Kühn', '35756'),
	(20007, 'Erich', 'Krause', '10627'),
	(20008, 'Elfriede', 'Thomas', '3046'),
	(20009, 'Werner', 'Schwarz', '58455'),
	(20010, 'Emelie', 'Bergmann', '76359');

