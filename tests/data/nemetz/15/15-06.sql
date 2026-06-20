PRAGMA page_size=4096;
PRAGMA page_size;
PRAGMA encoding="UTF-8";
PRAGMA encoding;
PRAGMA secure_delete=0;

CREATE TABLE 'users' (
	'id' INT UNSIGNED NOT NULL,
	'name' TEXT NOT NULL,
	'surname' TEXT NULL,
	'plz' INTEGER NULL,
	'code' INTEGER NULL
);

INSERT INTO 'users' 
	(id, name, surname, code)
	VALUES
	(20001, 'Noah', 'König', 3931244),
	(20002, 'Pia', 'Horn', 3091541),
	(20003, 'Lina', 'Berger', 1750176),
	(20004, 'Lotta', 'Huber', 2351133),
	(20005, 'Josef', 'Engel', 4302395),
	(20006, 'Maria', 'Schmid', 630709),
	(20007, 'Tobias', 'Schumacher', 2410254),
	(20008, 'Andre', 'Wagner', 1962795),
	(20009, 'Christian', 'Scholz', 5231964),
	(20010, 'Torsten', 'Lorenz', 3545907),
	(20011, 'Jonathan', 'Hoffmann', 5761034),
	(20012, 'Artur', 'Brandt', 1689828),
	(20013, 'Linus', 'Schmid', 2055296),
	(20014, 'Sabine', 'Heinrich', 3827265),
	(20015, 'Emilia', 'Schmitz', 4632578),
	(20016, 'Tanja', 'Kaiser', 2677009),
	(20017, 'Zoe', 'Hofmann', 1418665),
	(20018, 'Isabell', 'Jäger', 819682),
	(20019, 'Mats', 'Kuhn', 4993569),
	(20020, 'Leon', 'Krämer', 2022865);

