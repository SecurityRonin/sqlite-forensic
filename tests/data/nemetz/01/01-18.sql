PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE "
" (
	'id' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'zip' INT UNSIGNED NULL
);

INSERT INTO "
" 
	(id, name, surname, zip)
	VALUES
	(20001, 'Leon', 'Keller', '83677'),
	(20002, 'Lilly', 'Beck', '47559'),
	(20003, 'Nico', 'Otto', '84494'),
	(20004, 'Nico', 'Schmid', '74850'),
	(20005, 'Nadine', 'Schubert', '41542'),
	(20006, 'Jens', 'Jäger', '55571'),
	(20007, 'Wilhelm', 'Koch', '83368'),
	(20008, 'Sabine', 'Bergmann', '79289'),
	(20009, 'Gustav', 'Meyer', '25797'),
	(20010, 'Wilhelm', 'Lehmann', '2999');

