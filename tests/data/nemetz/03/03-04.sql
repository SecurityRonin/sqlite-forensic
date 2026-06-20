PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE 'users' (
	'id' INTEGER,
	'name' TEXT,
	'surname' TEXT UNIQUE,
	'zip' INTEGER
);

INSERT INTO 'users' 
	(id, name, surname, zip)
	VALUES
	(20001, 'Florian', 'Wolf', '53501'),
	(20002, 'Lotta', 'Albrecht', '6889'),
	(20003, 'Lilly', 'Martin', '83368'),
	(20004, 'Sven', 'Otto', '21079'),
	(20005, 'Clara', 'Mayer', '12623'),
	(20006, 'Nico', 'Pohl', '36132'),
	(20007, 'Fabian', 'König', '24867'),
	(20008, 'Adrian', 'Graf', '81739'),
	(20009, 'Emmi', 'Richter', '45770'),
	(20010, 'Johannes', 'Schmidt', '99759');

