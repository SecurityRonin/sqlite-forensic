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
	(20001, 'Marie', 'Meier', '66871'),
	(20002, 'Matthias', 'Stein', '97727'),
	(20003, 'Tobias', 'Kuhn', '40470'),
	(20004, 'Timo', 'Mayer', '98693'),
	(20005, 'Marlene', 'Kühn', '83544'),
	(20006, 'Andrea', 'Vogt', '16562'),
	(20007, 'Thomas', 'Ludwig', '67468'),
	(20008, 'Maximilian', 'Schmitt', '48151'),
	(20009, 'Florian', 'Roth', '56112'),
	(20010, 'Alexandra', 'Roth', '32683');

