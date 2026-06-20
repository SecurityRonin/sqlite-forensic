PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE 'users' (
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'number' "INTEGER(11,0)"
);

INSERT INTO 'users' 
	(name, surname, number)
	VALUES
	('Georg', 'Müller', 20001),
	('Luca', 'Schneider', 20002),
	('Michaela', 'Becker', 20003),
	('Walter', 'Stein', 20004),
	('Benjamin', 'Neumann', 20005),
	('Melanie', 'Seidel', 20006),
	('Mathilda', 'Sommer', 20007),
	('Sarah', 'Otto', 20008),
	('Erna', 'Graf', 20009),
	('Isabell', 'Köhler', 20010);

