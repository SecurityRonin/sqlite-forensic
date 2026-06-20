PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE "''" (
	'id' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'zip' INT UNSIGNED NULL
);

INSERT INTO "''" 
	(id, name, surname, zip)
	VALUES
	(20001, 'Sonja', 'Keller', '75394'),
	(20002, 'Katrin', 'Pohl', '86556'),
	(20003, 'Marc', 'Krämer', '57520'),
	(20004, 'David', 'Herrmann', '86931'),
	(20005, 'Erich', 'Möller', '55130'),
	(20006, 'Stefanie', 'Brandt', '9648'),
	(20007, 'Manuela', 'Kaiser', '49179'),
	(20008, 'Lilly', 'Groß', '9599'),
	(20009, 'Marc', 'Scholz', '40724'),
	(20010, 'Marie', 'Kuhn', '15890');

