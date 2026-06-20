PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE 'users' (
	'id' INTEGER PRIMARY KEY DESC,
	'name' TEXT,
	'surname' TEXT,
	'zip' INTEGER
);

INSERT INTO 'users' 
	(id, name, surname, zip)
	VALUES
	(20001, 'Julius', 'Otto', 24955),
	(20002, 'Elsa', 'Schneider', 98743),
	(20003, 'Hedwig', 'Richter', 25482),
	(20004, 'Rudolf', 'Becker', 99638),
	(20005, 'Emilia', 'Keller', 90765),
	(20006, 'Luise', 'Thomas', 25594),
	(20007, 'Josephine', 'Herrmann', 35440),
	(20008, 'Melanie', 'Schulze', 17309),
	(20009, 'Jannik', 'Haas', 42853),
	(20010, 'Sonja', 'Meier', 49324);

