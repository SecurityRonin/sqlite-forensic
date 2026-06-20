PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE 'A"b"c' (
	'id' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'zip' INT UNSIGNED NULL
);

INSERT INTO 'A"b"c' 
	(id, name, surname, zip)
	VALUES
	(20001, 'August', 'Lehmann', '83308'),
	(20002, 'Luise', 'Ludwig', '89520'),
	(20003, 'Manuela', 'Schmitz', '83364'),
	(20004, 'Pia', 'Brandt', '39418'),
	(20005, 'Greta', 'Roth', '79424'),
	(20006, 'Ida', 'Schmidt', '31636'),
	(20007, 'Walter', 'Schuster', '95482'),
	(20008, 'Gertrud', 'Zimmermann', '6888'),
	(20009, 'Berta', 'Schumacher', '56459'),
	(20010, 'Tobias', 'Mayer', '90491');

