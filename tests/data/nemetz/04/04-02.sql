PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-16be";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE 'utf16beTest' (
	'id' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'zip' INT UNSIGNED NULL
);

INSERT INTO 'utf16beTest' 
	(id, name, surname, zip)
	VALUES
	(20001, 'Katja', 'Werner', '27333'),
	(20002, 'Michael', 'Weiß', '24145'),
	(20003, 'Christine', 'Lange', '53619'),
	(20004, 'Markus', 'Meyer', '44147'),
	(20005, 'Silke', 'Engel', '38122'),
	(20006, 'Zoe', 'Vogt', '99831'),
	(20007, 'Luca', 'Schulze', '82389'),
	(20008, 'Mats', 'Wagner', '41517'),
	(20009, 'Stefanie', 'Schröder', '35108'),
	(20010, 'Alexandra', 'Wagner', '87669');
