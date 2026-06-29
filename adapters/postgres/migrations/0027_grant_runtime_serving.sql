-- Split migrator and serving roles: the long-lived app login inherits rss_app
-- runtime DML only, while migrations/DDL stay on the short-lived migrator role.
-- No schema CREATE, ownership, CREATEROLE, or BYPASSRLS grant is allowed here.

GRANT SELECT, INSERT, UPDATE, DELETE ON outbox TO rss_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON inbox_dedup TO rss_app;
GRANT SELECT, INSERT, UPDATE ON checkpoint TO rss_app;
GRANT SELECT, INSERT ON saga_journal TO rss_app;
GRANT SELECT, INSERT ON dead_letter TO rss_app;
