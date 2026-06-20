PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=1;
PRAGMA secure_delete;

CREATE TABLE "%s%s" (
	'id' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'zip' INT UNSIGNED NULL
);

INSERT INTO "%s%s" 
	(id, name, surname, zip)
	VALUES
	(20001, 'Anja', 'Graf', '99846'),
	(20002, 'Susanne', 'Schmitz', '98724'),
	(20003, 'Elisa', 'Lang', '66701'),
	(20004, 'Sascha', 'Martin', '23777'),
	(20005, 'Leon', 'Wagner', '6749'),
	(20006, 'Christina', 'Simon', '48231'),
	(20007, 'Maja', 'Huber', '93491'),
	(20008, 'Lia', 'Berger', '65629'),
	(20009, 'Gustav', 'Kühn', '51427'),
	(20010, 'Vincent', 'Sauer', '9579');

