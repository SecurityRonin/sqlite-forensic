PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=0;

CREATE TABLE 'users' (
	'id' INT UNSIGNED NOT NULL,
	'plz' INTEGER NULL,
	'codeA' INTEGER NULL,
	'codeB' INTEGER NULL
);

INSERT INTO 'users' 
	(id, plz, codeA, codeB)
	VALUES
	(20001, '92696', 5349609, 247),
	(20002, '8233', 64351276, 31),
	(20003, '76532', 19745302, 107),
	(20004, '86637', 12477333, 175),
	(20005, '32584', 21087741, 130),
	(20006, '66957', 57044134, 37),
	(20007, '71384', 38219991, 40),
	(20008, '55278', 32852704, 36),
	(20009, '17213', 65318801, 246),
	(20010, '24794', 66289297, 73);

CREATE TABLE 'members' (
	'mid' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL
);

INSERT INTO 'members' 
	(mid, name, surname)
	VALUES
	(30001, 'Katharina', 'Schäfer'),
	(30002, 'Hanna', 'Kühn'),
	(30003, 'Irma', 'Becker'),
	(30004, 'Lina', 'Bauer'),
	(30005, 'Finn', 'Ziegler'),
	(30006, 'Paul', 'Köhler'),
	(30007, 'Martina', 'Baumann'),
	(30008, 'Luisa', 'Friedrich'),
	(30009, 'Lina', 'Heinrich'),
	(30010, 'Hannes', 'Frank'),
	(30011, 'Mats', 'Lehmann'),
	(30012, 'Lisa', 'Beck'),
	(30013, 'Manuela', 'Roth'),
	(30014, 'Oskar', 'Neumann'),
	(30015, 'Nele', 'Müller');

