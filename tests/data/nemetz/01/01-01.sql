PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE '""' (
	'id' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'zip' INT UNSIGNED NULL
);

INSERT INTO '""' 
	(id, name, surname, zip)
	VALUES
	(20001, 'Max', 'Schulz', '67065'),
	(20002, 'Nico', 'Brandt', '53424'),
	(20003, 'Leo', 'Herrmann', '66954'),
	(20004, 'Michael', 'Voigt', '83242'),
	(20005, 'Simon', 'Herrmann', '94154'),
	(20006, 'Hertha', 'Otto', '83256'),
	(20007, 'Adrian', 'Otto', '35469'),
	(20008, 'Elli', 'Zimmermann', '64732'),
	(20009, 'Lisa', 'Frank', '99819'),
	(20010, 'Linus', 'Schwarz', '47929');





