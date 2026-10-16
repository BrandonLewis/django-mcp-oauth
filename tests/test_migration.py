"""The initial migration leaves tables that already exist alone, so a product
adopting the app from an in-tree copy can rename its tables and migrate."""

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.db.migrations.state import ProjectState
from django.test import TransactionTestCase


class InitialMigrationIsIdempotentTests(TransactionTestCase):
    def test_create_model_if_missing_skips_an_existing_table(self):
        executor = MigrationExecutor(connection)
        migration = executor.loader.get_migration("mcp_oauth", "0001_initial")
        target = executor.loader.project_state(("mcp_oauth", "0001_initial"))
        before = ProjectState(real_apps={"auth", "contenttypes"})
        # The test database already holds the tables: a plain CreateModel would
        # fail with "table already exists"; ours must return quietly.
        with connection.schema_editor() as editor:
            for op in migration.operations:
                op.database_forwards("mcp_oauth", editor, before, target)
        with connection.cursor() as cursor:
            names = connection.introspection.table_names(cursor)
        for table in (
            "mcp_oauth_oauth2client",
            "mcp_oauth_oauth2token",
            "mcp_oauth_oauth2authorizationcode",
        ):
            self.assertIn(table, names)

    def test_unapplying_never_drops_a_table(self):
        executor = MigrationExecutor(connection)
        migration = executor.loader.get_migration("mcp_oauth", "0001_initial")
        applied = executor.loader.project_state(("mcp_oauth", "0001_initial"))
        before = ProjectState(real_apps={"auth", "contenttypes"})
        with connection.schema_editor() as editor:
            for op in reversed(migration.operations):
                op.database_backwards("mcp_oauth", editor, applied, before)
        with connection.cursor() as cursor:
            names = connection.introspection.table_names(cursor)
        self.assertIn("mcp_oauth_oauth2client", names)
