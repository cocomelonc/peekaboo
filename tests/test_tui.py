from __future__ import annotations

import unittest

try:
    from textual.widgets import DataTable, Input, RichLog

    from peekaboo_tui import (
        AssistantScreen,
        Column,
        DetailScreen,
        PeekabooApp,
        SourceScreen,
        ViewData,
    )

    TEXTUAL_AVAILABLE = True
except ModuleNotFoundError:
    TEXTUAL_AVAILABLE = False


class FakeRepository:
    def header_status(self) -> str:
        return "DB 1 MB | 1 campaign | 2 modules | 3 detections"

    def load(self, view: str) -> ViewData:
        columns = (
            Column("id", "ID", 16),
            Column("name", "NAME", 32),
        )
        source_record = {
            "slug": f"{view}-alpha",
            "blog_slug": f"{view}-alpha",
            "title": "Alpha process injection",
            "src_path": "alpha.c",
            "snippet": (
                "#include <stdio.h>\n\n"
                "int main(void) {\n"
                '    puts("alpha");\n'
                "    return 0;\n"
                "}\n\n"
                + "\n".join(f"// source line {line:03d}" for line in range(1, 90))
                + "\n// "
                + ("wide-source-column-" * 16)
            ),
        }
        rows = [
            {
                "key": f"{view}-alpha",
                "cells": (f"{view}-1", "Alpha process injection"),
                "search": f"{view} alpha process injection t1055",
                "detail": f"# {view} alpha\n\nFirst detail.",
                "context": {
                    "record": source_record,
                    "slug": source_record["slug"],
                },
            },
            {
                "key": f"{view}-beta",
                "cells": (f"{view}-2", "Beta persistence"),
                "search": f"{view} beta persistence t1547",
                "detail": f"# {view} beta\n\nSecond detail.",
                "context": {},
            },
        ]
        return ViewData(view.title(), f"{view} subtitle", columns, rows)


@unittest.skipUnless(TEXTUAL_AVAILABLE, "Textual is not installed")
class TuiContractTests(unittest.IsolatedAsyncioTestCase):
    async def test_navigation_search_detail_and_assistant(self) -> None:
        app = PeekabooApp(FakeRepository())
        async with app.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            self.assertEqual(app.current_view, "overview")
            self.assertEqual(app.query_one(DataTable).row_count, 2)

            for key, view in zip(
                "234567891",
                (
                    "campaigns",
                    "library",
                    "attack",
                    "detection",
                    "intel",
                    "builds",
                    "samples",
                    "tools",
                    "overview",
                ),
            ):
                await pilot.press(key)
                await pilot.pause()
                self.assertEqual(app.current_view, view)

            await pilot.press("/", "a", "l", "p", "h", "a")
            await pilot.pause()
            self.assertEqual(app.query_one(Input).value, "alpha")
            self.assertEqual(app.query_one(DataTable).row_count, 1)

            await pilot.press("enter", "enter")
            await pilot.pause()
            self.assertIsInstance(app.screen, DetailScreen)
            await pilot.press("escape", "a")
            await pilot.pause()
            self.assertIsInstance(app.screen, AssistantScreen)
            await pilot.press("escape")
            await pilot.pause()
            self.assertEqual(app.current_view, "overview")

    async def test_compact_layout_keeps_table_navigation(self) -> None:
        app = PeekabooApp(FakeRepository(), initial_view="library")
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            self.assertTrue(app.query_one("#shell").has_class("compact"))
            self.assertEqual(app.query_one(DataTable).row_count, 2)

            await pilot.press("]")
            await pilot.pause()
            self.assertEqual(app.current_view, "attack")

            await pilot.press("j")
            await pilot.pause()
            self.assertEqual(app.query_one(DataTable).cursor_row, 1)

    async def test_monokai_source_viewer_uses_snippet_fallback(self) -> None:
        app = PeekabooApp(FakeRepository(), initial_view="library")
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await pilot.press("s")
            await pilot.pause()

            self.assertIsInstance(app.screen, SourceScreen)
            self.assertEqual(app.screen.language, "c")
            self.assertIn("int main", app.screen.source)
            source_log = app.screen.query_one("#source-code", RichLog)
            self.assertGreater(len(source_log.lines), 0)
            self.assertTrue(source_log.has_focus)
            self.assertGreater(source_log.max_scroll_y, 0)
            self.assertGreater(source_log.max_scroll_x, 0)

            await pilot.press("end", "ctrl+pagedown")
            await pilot.pause()
            self.assertGreater(source_log.scroll_y, 0)
            self.assertGreater(source_log.scroll_x, 0)

            await pilot.press("escape")
            await pilot.pause()
            self.assertIs(app.screen, app.screen_stack[0])

    async def test_help_is_a_dismissible_modal(self) -> None:
        app = PeekabooApp(FakeRepository())
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await pilot.press("?")
            await pilot.pause()
            self.assertIsInstance(app.screen, DetailScreen)
            await pilot.press("q")
            await pilot.pause()
            self.assertIs(app.screen, app.screen_stack[0])

    async def test_offline_canned_assistant_response(self) -> None:
        app = PeekabooApp(FakeRepository(), offline=True)
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await pilot.press("a")
            await pilot.pause()
            assistant = app.screen
            self.assertIsInstance(assistant, AssistantScreen)

            field = assistant.query_one("#assistant-input", Input)
            field.value = "what is peekaboo?"
            await pilot.press("enter")
            await pilot.pause(2)

            self.assertEqual(
                [message["role"] for message in assistant.messages],
                ["user", "assistant"],
            )
            self.assertIn("APT Simulation Framework", assistant.messages[-1]["content"])
            self.assertFalse(field.disabled)


if __name__ == "__main__":
    unittest.main()
