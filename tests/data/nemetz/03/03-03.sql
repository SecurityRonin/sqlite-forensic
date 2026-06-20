PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE 'users' (
	'id' INTEGER,
	'name' TEXT,
	'surname' TEXT UNIQUE_NAME,
	'zip' INTEGER
);

INSERT INTO 'users' 
	(id, name, surname, zip)
	VALUES
	(20001, 'Eric', 'Haas', '49205'),
	(20002, 'Leo', 'Braun', '85643'),
	(20003, 'Melina', 'Klein', '86574'),
	(20004, 'Susanne', 'Krämer', '95336'),
	(20005, 'Björn', 'Groß', '21409'),
	(20006, 'Lisa', 'Lang', '42329'),
	(20007, 'Sabine', 'Schmid', '35585'),
	(20008, 'Kerstin', 'Franke', '56283'),
	(20009, 'Nele', 'König', '27793'),
	(20010, 'Friedrich', 'Brandt', '95659');

