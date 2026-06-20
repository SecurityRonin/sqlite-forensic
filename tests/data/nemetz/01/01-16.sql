PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE "	" (
	'id' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'zip' INT UNSIGNED NULL
);

INSERT INTO "	" 
	(id, name, surname, zip)
	VALUES
	(20001, 'Tanja', 'Pfeiffer', '32120'),
	(20002, 'Mats', 'Schuster', '80689'),
	(20003, 'Tom', 'Franke', '94436'),
	(20004, 'Finja', 'König', '38322'),
	(20005, 'Jessica', 'Friedrich', '71717'),
	(20006, 'Sarah', 'Roth', '55257'),
	(20007, 'Sonja', 'Pohl', '24594'),
	(20008, 'Ida', 'Meyer', '25572'),
	(20009, 'Jonathan', 'Thomas', '42107'),
	(20010, 'Marlene', 'Scholz', '97342');

