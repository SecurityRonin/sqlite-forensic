PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE "--" (
	'id' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'zip' INT UNSIGNED NULL
);

INSERT INTO "--" 
	(id, name, surname, zip)
	VALUES
	(20001, 'Elias', 'Simon', '24247'),
	(20002, 'Silvia', 'Werner', '90599'),
	(20003, 'Lotta', 'Kaiser', '91487'),
	(20004, 'Josephine', 'Köhler', '63579'),
	(20005, 'Niklas', 'Jung', '95126'),
	(20006, 'Paul', 'Keller', '71101'),
	(20007, 'Amelie', 'Wolf', '95494'),
	(20008, 'Niklas', 'Möller', '59063'),
	(20009, 'Lilly', 'Horn', '8359'),
	(20010, 'Marco', 'Maier', '21441');

