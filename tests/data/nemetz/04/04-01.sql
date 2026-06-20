PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-16le";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE 'utf16leTest' (
	'id' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'zip' INT UNSIGNED NULL
);

INSERT INTO 'utf16leTest' 
	(id, name, surname, zip)
	VALUES
	(20001, 'Stefanie', 'Berger', '54689'),
	(20002, 'Ida', 'Mayer', '6618'),
	(20003, 'Anne', 'Wolff', '65611'),
	(20004, 'Jana', 'Schwarz', '79282'),
	(20005, 'Nina', 'Richter', '79279'),
	(20006, 'Katharina', 'Graf', '87719'),
	(20007, 'Liam', 'Scholz', '92700'),
	(20008, 'Daniela', 'Horn', '24800'),
	(20009, 'Vincent', 'Frank', '89614'),
	(20010, 'Lena', 'Stein', '4159');
