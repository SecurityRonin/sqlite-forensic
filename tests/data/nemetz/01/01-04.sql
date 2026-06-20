PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE ']' (
	'id' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'zip' INT UNSIGNED NULL
);

INSERT INTO ']' 
	(id, name, surname, zip)
	VALUES
	(20001, 'Isabella', 'Schuster', '9627'),
	(20002, 'Max', 'Schwarz', '1824'),
	(20003, 'Anni', 'Simon', '79843'),
	(20004, 'Irma', 'Thomas', '52224'),
	(20005, 'Jörg', 'Weber', '36115'),
	(20006, 'Theo', 'Fischer', '38116'),
	(20007, 'Heinrich', 'Mayer', '35444'),
	(20008, 'Josephine', 'Mayer', '6179'),
	(20009, 'Artur', 'Meyer', '38378'),
	(20010, 'Susanne', 'Weiß', '56859');

